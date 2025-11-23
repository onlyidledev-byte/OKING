// server.js - Main Express Server
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL Connection Pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3001',
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Session Configuration
app.use(session({
  store: new pgSession({
    pool: pool,
    tableName: 'session'
  }),
  secret: process.env.SESSION_SECRET || 'otp-king-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true
  }
}));

// File Upload Configuration
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB
});

// Rate Limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests, please try again later.'
});

app.use('/api/', apiLimiter);

// Database Initialization
const initializeDatabase = async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(100),
        credits INTEGER DEFAULT 100,
        referrals INTEGER DEFAULT 0,
        numbers_used INTEGER DEFAULT 0,
        banned BOOLEAN DEFAULT FALSE,
        is_admin BOOLEAN DEFAULT FALSE,
        ip_address VARCHAR(45),
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS countries (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        code VARCHAR(10) NOT NULL,
        flag VARCHAR(10) NOT NULL,
        key VARCHAR(10) UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS number_sets (
        id SERIAL PRIMARY KEY,
        country_id INTEGER REFERENCES countries(id) ON DELETE CASCADE,
        numbers TEXT NOT NULL,
        total_count INTEGER NOT NULL,
        used_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS number_usage (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        number_set_id INTEGER REFERENCES number_sets(id) ON DELETE CASCADE,
        phone_number VARCHAR(20) NOT NULL,
        used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS sms_messages (
        id SERIAL PRIMARY KEY,
        phone_number VARCHAR(20) NOT NULL,
        sender VARCHAR(100),
        message TEXT,
        received_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS announcements (
        id SERIAL PRIMARY KEY,
        text TEXT NOT NULL,
        active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255),
        message TEXT NOT NULL,
        read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS promo_codes (
        id SERIAL PRIMARY KEY,
        code VARCHAR(50) UNIQUE NOT NULL,
        credits INTEGER NOT NULL,
        max_uses INTEGER NOT NULL,
        current_uses INTEGER DEFAULT 0,
        expires_at TIMESTAMP,
        active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS promo_usage (
        id SERIAL PRIMARY KEY,
        promo_code_id INTEGER REFERENCES promo_codes(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(promo_code_id, user_id)
      );

      CREATE TABLE IF NOT EXISTS settings (
        id SERIAL PRIMARY KEY,
        key VARCHAR(100) UNIQUE NOT NULL,
        value TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS chat_messages (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        message TEXT NOT NULL,
        is_admin BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        amount DECIMAL(10, 2) NOT NULL,
        credits INTEGER NOT NULL,
        reference VARCHAR(255) UNIQUE NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS ip_tracking (
        id SERIAL PRIMARY KEY,
        ip_address VARCHAR(45) NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Insert default admin user if not exists
      INSERT INTO users (username, password, is_admin, credits)
      VALUES ('idledev', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', true, 999999)
      ON CONFLICT (username) DO NOTHING;

      -- Insert default settings
      INSERT INTO settings (key, value) VALUES 
        ('sms_api_token', 'QlZSNEVBcHJHbIuGSoxYZVZlk4iFamd1U2lYU0iLk4hfjnFCSXA='),
        ('credit_amount', '1000'),
        ('credit_price', '1000'),
        ('referral_credits', '100'),
        ('daily_credits', '50'),
        ('maintenance_mode', 'false')
      ON CONFLICT (key) DO NOTHING;

      -- Insert default countries
      INSERT INTO countries (name, code, flag, key) VALUES
        ('United States', '+1', '🇺🇸', 'us'),
        ('United Kingdom', '+44', '🇬🇧', 'uk'),
        ('Nigeria', '+234', '🇳🇬', 'ng'),
        ('Canada', '+1', '🇨🇦', 'ca'),
        ('Germany', '+49', '🇩🇪', 'de'),
        ('France', '+33', '🇫🇷', 'fr'),
        ('India', '+91', '🇮🇳', 'in'),
        ('China', '+86', '🇨🇳', 'cn')
      ON CONFLICT (key) DO NOTHING;
    `);
    console.log('✅ Database initialized successfully');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
  } finally {
    client.release();
  }
};

// Middleware: Check if user is authenticated
const isAuthenticated = (req, res, next) => {
  if (req.session.userId) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

// Middleware: Check if user is admin
const isAdmin = async (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  const result = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.session.userId]);
  if (result.rows[0]?.is_admin) {
    next();
  } else {
    res.status(403).json({ error: 'Forbidden: Admin access required' });
  }
};

// Helper: Get client IP
const getClientIP = (req) => {
  return req.headers['x-forwarded-for']?.split(',')[0] || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress;
};

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password, referralCode } = req.body;
    const ip = getClientIP(req);

    // Check if IP already has an account
    const ipCheck = await pool.query(
      'SELECT COUNT(*) as count FROM ip_tracking WHERE ip_address = $1',
      [ip]
    );
    
    if (parseInt(ipCheck.rows[0].count) >= 1) {
      return res.status(400).json({ error: 'Multiple accounts from same IP detected' });
    }

    // Check if username exists
    const userExists = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Get daily credits setting
    const dailyCreditsResult = await pool.query("SELECT value FROM settings WHERE key = 'daily_credits'");
    const dailyCredits = parseInt(dailyCreditsResult.rows[0]?.value || 50);

    // Create user
    const result = await pool.query(
      'INSERT INTO users (username, password, ip_address, credits) VALUES ($1, $2, $3, $4) RETURNING id, username, credits',
      [username, hashedPassword, ip, 100]
    );

    const newUser = result.rows[0];

    // Track IP
    await pool.query('INSERT INTO ip_tracking (ip_address, user_id) VALUES ($1, $2)', [ip, newUser.id]);

    // Handle referral
    if (referralCode) {
      const referrer = await pool.query('SELECT id FROM users WHERE username = $1', [referralCode]);
      if (referrer.rows.length > 0) {
        const referralCreditsResult = await pool.query("SELECT value FROM settings WHERE key = 'referral_credits'");
        const referralCredits = parseInt(referralCreditsResult.rows[0]?.value || 100);
        
        await pool.query(
          'UPDATE users SET credits = credits + $1, referrals = referrals + 1 WHERE id = $2',
          [referralCredits, referrer.rows[0].id]
        );
      }
    }

    req.session.userId = newUser.id;
    res.json({ success: true, user: newUser });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const ip = getClientIP(req);

    const result = await pool.query(
      'SELECT id, username, password, credits, is_admin, banned FROM users WHERE username = $1',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    if (user.banned && !user.is_admin) {
      return res.status(403).json({ error: 'Account has been banned' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check maintenance mode
    const maintenanceResult = await pool.query("SELECT value FROM settings WHERE key = 'maintenance_mode'");
    const maintenanceMode = maintenanceResult.rows[0]?.value === 'true';
    
    if (maintenanceMode && !user.is_admin) {
      return res.status(503).json({ error: 'Site is under maintenance' });
    }

    // Check daily login credits
    const lastLogin = await pool.query('SELECT last_login FROM users WHERE id = $1', [user.id]);
    const lastLoginDate = lastLogin.rows[0]?.last_login;
    const today = new Date().toDateString();
    
    if (!lastLoginDate || new Date(lastLoginDate).toDateString() !== today) {
      const dailyCreditsResult = await pool.query("SELECT value FROM settings WHERE key = 'daily_credits'");
      const dailyCredits = parseInt(dailyCreditsResult.rows[0]?.value || 50);
      
      await pool.query(
        'UPDATE users SET credits = credits + $1, last_login = CURRENT_TIMESTAMP WHERE id = $2',
        [dailyCredits, user.id]
      );
      user.credits += dailyCredits;
    } else {
      await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);
    }

    req.session.userId = user.id;
    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        credits: user.credits,
        isAdmin: user.is_admin
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Get current user
app.get('/api/auth/me', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, credits, referrals, numbers_used, is_admin FROM users WHERE id = $1',
      [req.session.userId]
    );
    res.json({ user: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// ==================== NUMBER ROUTES ====================

// Get all number sets
app.get('/api/numbers', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT ns.id, ns.total_count, ns.used_count, ns.created_at,
             c.name, c.code, c.flag, c.key
      FROM number_sets ns
      JOIN countries c ON ns.country_id = c.id
      ORDER BY ns.created_at DESC
    `);

    const numberSets = result.rows.map(row => ({
      id: row.id,
      country: {
        name: row.name,
        code: row.code,
        flag: row.flag,
        key: row.key
      },
      totalCount: row.total_count,
      usedCount: row.used_count,
      createdAt: row.created_at
    }));

    res.json({ numberSets });
  } catch (error) {
    console.error('Fetch numbers error:', error);
    res.status(500).json({ error: 'Failed to fetch numbers' });
  }
});

// Upload numbers (Admin only)
app.post('/api/numbers/upload', isAdmin, upload.single('file'), async (req, res) => {
  try {
    const { countryKey } = req.body;
    const fileContent = req.file.buffer.toString('utf8');
    const numbers = fileContent.split('\n').filter(n => n.trim()).map(n => n.trim());

    const countryResult = await pool.query('SELECT id FROM countries WHERE key = $1', [countryKey]);
    if (countryResult.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid country' });
    }

    const countryId = countryResult.rows[0].id;
    const numbersJson = JSON.stringify(numbers);

    const result = await pool.query(
      'INSERT INTO number_sets (country_id, numbers, total_count) VALUES ($1, $2, $3) RETURNING id',
      [countryId, numbersJson, numbers.length]
    );

    res.json({ success: true, id: result.rows[0].id, count: numbers.length });
  } catch (error) {
    console.error('Upload numbers error:', error);
    res.status(500).json({ error: 'Failed to upload numbers' });
  }
});

// Get random number from set
app.post('/api/numbers/:setId/random', isAuthenticated, async (req, res) => {
  try {
    const { setId } = req.params;
    const userId = req.session.userId;

    // Check user credits
    const userResult = await pool.query('SELECT credits FROM users WHERE id = $1', [userId]);
    if (userResult.rows[0].credits < 1) {
      return res.status(400).json({ error: 'Insufficient credits' });
    }

    // Get number set
    const setResult = await pool.query(
      'SELECT numbers, total_count, used_count FROM number_sets WHERE id = $1',
      [setId]
    );

    if (setResult.rows.length === 0) {
      return res.status(404).json({ error: 'Number set not found' });
    }

    const numbers = JSON.parse(setResult.rows[0].numbers);
    const availableNumbers = numbers.slice(setResult.rows[0].used_count);

    if (availableNumbers.length === 0) {
      return res.status(400).json({ error: 'No numbers available' });
    }

    const randomNumber = availableNumbers[Math.floor(Math.random() * availableNumbers.length)];

    // Deduct credit and update usage
    await pool.query('UPDATE users SET credits = credits - 1, numbers_used = numbers_used + 1 WHERE id = $1', [userId]);
    await pool.query('UPDATE number_sets SET used_count = used_count + 1 WHERE id = $1', [setId]);
    await pool.query(
      'INSERT INTO number_usage (user_id, number_set_id, phone_number) VALUES ($1, $2, $3)',
      [userId, setId, randomNumber]
    );

    res.json({ number: randomNumber });
  } catch (error) {
    console.error('Get random number error:', error);
    res.status(500).json({ error: 'Failed to get number' });
  }
});

// Delete number set (Admin only)
app.delete('/api/numbers/:setId', isAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM number_sets WHERE id = $1', [req.params.setId]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete number set' });
  }
});

// ==================== SMS ROUTES ====================

// Check SMS for number
app.post('/api/sms/check', isAuthenticated, async (req, res) => {
  try {
    const { phoneNumber } = req.body;

    // Get SMS API token
    const tokenResult = await pool.query("SELECT value FROM settings WHERE key = 'sms_api_token'");
    const token = tokenResult.rows[0]?.value;

    const response = await axios.get('http://51.77.216.195/crapi/dgroup/viewstats', {
      params: {
        token: token,
        filternum: phoneNumber,
        records: 20
      }
    });

    if (response.data.status === 'success' && response.data.data) {
      // Save to database
      for (const sms of response.data.data) {
        await pool.query(
          'INSERT INTO sms_messages (phone_number, sender, message, received_at) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING',
          [sms.num, sms.cli, sms.message, sms.dt]
        );
      }

      res.json({ success: true, messages: response.data.data });
    } else {
      res.json({ success: true, messages: [] });
    }
  } catch (error) {
    console.error('Check SMS error:', error);
    res.status(500).json({ error: 'Failed to check SMS' });
  }
});

// Get SMS history for number
app.get('/api/sms/:phoneNumber', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM sms_messages WHERE phone_number = $1 ORDER BY received_at DESC LIMIT 50',
      [req.params.phoneNumber]
    );
    res.json({ messages: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch SMS history' });
  }
});

// ==================== WALLET & PAYMENT ROUTES ====================

// Get wallet info
app.get('/api/wallet', isAuthenticated, async (req, res) => {
  try {
    const userResult = await pool.query('SELECT credits, referrals FROM users WHERE id = $1', [req.session.userId]);
    const settingsResult = await pool.query("SELECT key, value FROM settings WHERE key IN ('credit_amount', 'credit_price', 'referral_credits')");
    
    const settings = {};
    settingsResult.rows.forEach(row => {
      settings[row.key] = row.value;
    });

    res.json({
      credits: userResult.rows[0].credits,
      referrals: userResult.rows[0].referrals,
      creditAmount: parseInt(settings.credit_amount || 1000),
      creditPrice: parseInt(settings.credit_price || 1000),
      referralCredits: parseInt(settings.referral_credits || 100)
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch wallet info' });
  }
});

// Verify Paystack payment
app.post('/api/wallet/verify-payment', isAuthenticated, async (req, res) => {
  try {
    const { reference } = req.body;
    
    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
        }
      }
    );

    if (response.data.data.status === 'success') {
      const amount = response.data.data.amount / 100; // Convert from kobo to naira
      
      const settingsResult = await pool.query("SELECT value FROM settings WHERE key = 'credit_amount'");
      const creditAmount = parseInt(settingsResult.rows[0]?.value || 1000);

      await pool.query('UPDATE users SET credits = credits + $1 WHERE id = $2', [creditAmount, req.session.userId]);
      await pool.query(
        'INSERT INTO payments (user_id, amount, credits, reference, status) VALUES ($1, $2, $3, $4, $5)',
        [req.session.userId, amount, creditAmount, reference, 'completed']
      );

      res.json({ success: true, credits: creditAmount });
    } else {
      res.status(400).json({ error: 'Payment verification failed' });
    }
  } catch (error) {
    console.error('Payment verification error:', error);
    res.status(500).json({ error: 'Failed to verify payment' });
  }
});

// Apply promo code
app.post('/api/wallet/promo', isAuthenticated, async (req, res) => {
  try {
    const { code } = req.body;
    const userId = req.session.userId;

    const promoResult = await pool.query(
      'SELECT id, credits, max_uses, current_uses, expires_at, active FROM promo_codes WHERE code = $1',
      [code]
    );

    if (promoResult.rows.length === 0) {
      return res.status(404).json({ error: 'Invalid promo code' });
    }

    const promo = promoResult.rows[0];

    if (!promo.active) {
      return res.status(400).json({ error: 'Promo code is inactive' });
    }

    if (promo.current_uses >= promo.max_uses) {
      return res.status(400).json({ error: 'Promo code has been fully redeemed' });
    }

    if (promo.expires_at && new Date(promo.expires_at) < new Date()) {
      return res.status(400).json({ error: 'Promo code has expired' });
    }

    // Check if user already used this promo
    const usageCheck = await pool.query(
      'SELECT id FROM promo_usage WHERE promo_code_id = $1 AND user_id = $2',
      [promo.id, userId]
    );

    if (usageCheck.rows.length > 0) {
      return res.status(400).json({ error: 'You have already used this promo code' });
    }

    // Apply promo
    await pool.query('UPDATE users SET credits = credits + $1 WHERE id = $2', [promo.credits, userId]);
    await pool.query('UPDATE promo_codes SET current_uses = current_uses + 1 WHERE id = $1', [promo.id]);
    await pool.query('INSERT INTO promo_usage (promo_code_id, user_id) VALUES ($1, $2)', [promo.id, userId]);

    res.json({ success: true, credits: promo.credits });
  } catch (error) {
    console.error('Promo code error:', error);
    res.status(500).json({ error: 'Failed to apply promo code' });
  }
});

// ==================== ADMIN ROUTES ====================

// Get all users (Admin)
app.get('/api/admin/users', isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, credits, referrals, numbers_used, banned, created_at FROM users WHERE is_admin = false ORDER BY created_at DESC'
    );
    res.json({ users: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Ban/Unban user (Admin)
app.post('/api/admin/users/:userId/ban', isAdmin, async (req, res) => {
  try {
    const { banned } = req.body;
    await pool.query('UPDATE users SET banned = $1 WHERE id = $2', [banned, req.params.userId]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// Gift credits (Admin)
app.post('/api/admin/users/:userId/gift', isAdmin, async (req, res) => {
  try {
    const { amount } = req.body;
    await pool.query('UPDATE users SET credits = credits + $1 WHERE id = $2', [amount, req.params.userId]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to gift credits' });
  }
});

// Create promo code (Admin)
app.post('/api/admin/promo', isAdmin, async (req, res) => {
  try {
    const { code, credits, maxUses, expiresAt } = req.body;
    await pool.query(
      'INSERT INTO promo_codes (code, credits, max_uses, expires_at) VALUES ($1, $2, $3, $4)',
      [code, credits, maxUses, expiresAt || null]
    );
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create promo code' });
  }
});

// Get promo codes (Admin)
app.get('/api/admin/promo', isAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM promo_codes ORDER BY created_at DESC');
    res.json({ promoCodes: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch promo codes' });
  }
});

// Delete promo code (Admin)
app.delete('/api/admin/promo/:id', isAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM promo_codes WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete promo code' });
  }
});

// Update settings (Admin)
app.post('/api/admin/settings', isAdmin, async (req, res) => {
  try {
    const { key, value } = req.body;
    await pool.query(
      'INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP',
      [key, value]
    );
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

// Get settings
app.get('/api/settings', async (req, res) => {
  try {
    const result = await pool.query('SELECT key, value FROM settings');
    const settings = {};
    result.rows.forEach(row => {
      settings[row.key] = row.value;
    });
    res.json({ settings });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

// Create announcement (Admin)
app.post('/api/admin/announcements', isAdmin, async (req, res) => {
  try {
    const { text } = req.body;
    const result = await pool.query(
      'INSERT INTO announcements (text) VALUES ($1) RETURNING id',
      [text]
    );
    res.json({ success: true, id: result.rows[0].id });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create announcement' });
  }
});

// Get announcements
app.get('/api/announcements', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM announcements WHERE active = true ORDER BY created_at DESC');
    res.json({ announcements: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch announcements' });
  }
});

// Update announcement (Admin)
app.put('/api/admin/announcements/:id', isAdmin, async (req, res) => {
  try {
    const { text } = req.body;
    await pool.query('UPDATE announcements SET text = $1 WHERE id = $2', [text, req.params.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update announcement' });
  }
});

// Delete announcement (Admin)
app.delete('/api/admin/announcements/:id', isAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM announcements WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete announcement' });
  }
});

// Send notification to all users (Admin)
app.post('/api/admin/notifications/broadcast', isAdmin, async (req, res) => {
  try {
    const { title, message } = req.body;
    const usersResult = await pool.query('SELECT id FROM users WHERE is_admin = false');
    
    for (const user of usersResult.rows) {
      await pool.query(
        'INSERT INTO notifications (user_id, title, message) VALUES ($1, $2, $3)',
        [user.id, title, message]
      );
    }
    
    res.json({ success: true, count: usersResult.rows.length });
  } catch (error) {
    res.status(500).json({ error: 'Failed to send notifications' });
  }
});

// Get user notifications
app.get('/api/notifications', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM notifications WHERE user_id = $1 ORDER BY created_at DESC LIMIT 50',
      [req.session.userId]
    );
    res.json({ notifications: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch notifications' });
  }
});

// Mark notification as read
app.put('/api/notifications/:id/read', isAuthenticated, async (req, res) => {
  try {
    await pool.query(
      'UPDATE notifications SET read = true WHERE id = $1 AND user_id = $2',
      [req.params.id, req.session.userId]
    );
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to mark notification as read' });
  }
});

// Get unread notification count
app.get('/api/notifications/unread/count', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT COUNT(*) as count FROM notifications WHERE user_id = $1 AND read = false',
      [req.session.userId]
    );
    res.json({ count: parseInt(result.rows[0].count) });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch unread count' });
  }
});

// ==================== CHAT ROUTES ====================

// Send chat message
app.post('/api/chat', isAuthenticated, async (req, res) => {
  try {
    const { message } = req.body;
    const result = await pool.query(
      'INSERT INTO chat_messages (user_id, message, is_admin) VALUES ($1, $2, false) RETURNING *',
      [req.session.userId, message]
    );
    res.json({ success: true, message: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Get chat messages for user
app.get('/api/chat', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT cm.*, u.username FROM chat_messages cm JOIN users u ON cm.user_id = u.id WHERE cm.user_id = $1 ORDER BY cm.created_at ASC',
      [req.session.userId]
    );
    res.json({ messages: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Get all chat messages (Admin)
app.get('/api/admin/chat', isAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT cm.*, u.username 
      FROM chat_messages cm 
      JOIN users u ON cm.user_id = u.id 
      ORDER BY cm.created_at DESC 
      LIMIT 200
    `);
    res.json({ messages: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Reply to user chat (Admin)
app.post('/api/admin/chat/reply', isAdmin, async (req, res) => {
  try {
    const { userId, message } = req.body;
    const result = await pool.query(
      'INSERT INTO chat_messages (user_id, message, is_admin) VALUES ($1, $2, true) RETURNING *',
      [userId, message]
    );
    res.json({ success: true, message: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to send reply' });
  }
});

// ==================== STATISTICS ROUTES ====================

// Get admin statistics
app.get('/api/admin/stats', isAdmin, async (req, res) => {
  try {
    const totalUsers = await pool.query('SELECT COUNT(*) as count FROM users WHERE is_admin = false');
    const totalNumbers = await pool.query('SELECT SUM(total_count) as count FROM number_sets');
    const totalCreditsSpent = await pool.query('SELECT SUM(numbers_used) as count FROM users');
    const activeUsers = await pool.query('SELECT COUNT(*) as count FROM users WHERE last_login > NOW() - INTERVAL \'7 days\' AND is_admin = false');
    const recentPayments = await pool.query('SELECT SUM(amount) as total FROM payments WHERE created_at > NOW() - INTERVAL \'30 days\' AND status = \'completed\'');
    
    const mostUsedCountries = await pool.query(`
      SELECT c.name, c.flag, COUNT(nu.id) as usage_count
      FROM number_usage nu
      JOIN number_sets ns ON nu.number_set_id = ns.id
      JOIN countries c ON ns.country_id = c.id
      GROUP BY c.id, c.name, c.flag
      ORDER BY usage_count DESC
      LIMIT 5
    `);

    const topUsers = await pool.query(`
      SELECT username, numbers_used, credits, referrals
      FROM users
      WHERE is_admin = false
      ORDER BY numbers_used DESC
      LIMIT 10
    `);

    res.json({
      totalUsers: parseInt(totalUsers.rows[0].count),
      totalNumbers: parseInt(totalNumbers.rows[0].count || 0),
      totalCreditsSpent: parseInt(totalCreditsSpent.rows[0].count || 0),
      activeUsers: parseInt(activeUsers.rows[0].count),
      revenue: parseFloat(recentPayments.rows[0].total || 0),
      mostUsedCountries: mostUsedCountries.rows,
      topUsers: topUsers.rows
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

// Get user history
app.get('/api/user/history', isAuthenticated, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT nu.phone_number, nu.used_at, c.name, c.flag, c.code
      FROM number_usage nu
      JOIN number_sets ns ON nu.number_set_id = ns.id
      JOIN countries c ON ns.country_id = c.id
      WHERE nu.user_id = $1
      ORDER BY nu.used_at DESC
      LIMIT 50
    `, [req.session.userId]);

    res.json({ history: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch history' });
  }
});

// Get countries
app.get('/api/countries', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM countries ORDER BY name ASC');
    res.json({ countries: result.rows });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch countries' });
  }
});

// ==================== ERROR HANDLING ====================

app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ==================== START SERVER ====================

const startServer = async () => {
  try {
    await initializeDatabase();
    app.listen(PORT, () => {
      console.log(`🚀 OTP King Server running on port ${PORT}`);
      console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing server...');
  pool.end(() => {
    console.log('Database pool closed');
    process.exit(0);
  });
});

module.exports = app;
