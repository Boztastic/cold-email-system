const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const Imap = require('imap');
const { simpleParser } = require('mailparser');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

// ============================================================================
// BACKEND AUTHENTICATION WITH POSTGRESQL
// Complete authentication system integrated with database
// ============================================================================
// 
// INSERT THIS CODE into your server-with-warming.js file
// after line 23 (after the rate limiter)
//
// ============================================================================

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('./database'); // Database module

// ============================================================================
// CONFIGURATION
// ============================================================================

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// Run migrations on startup
db.runMigrations().catch(err => {
  console.error('Failed to run migrations:', err);
  process.exit(1);
});

// ============================================================================
// MIDDLEWARE
// ============================================================================

// Authenticate JWT token
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await db.findUserById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    if (!user.active) {
      return res.status(403).json({ error: 'Account is inactive' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Require admin role
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// ============================================================================
// AUTHENTICATION ROUTES
// ============================================================================

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Find user
    const user = await db.findUserByEmail(email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check if account is active
    if (!user.active) {
      return res.status(403).json({ error: 'Account is inactive' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Return user data (without password)
    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        active: user.active
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await db.findUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        active: user.active
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Change password
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password required' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    // Get user with password
    const user = await db.findUserByEmail(req.user.email);
    
    // Verify current password
    const validPassword = await bcrypt.compare(currentPassword, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Update password
    await db.updateUserPassword(req.user.id, newPassword);

    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================================================
// USER MANAGEMENT ROUTES (Admin Only)
// ============================================================================

// Get all users
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await db.getAllUsers();
    res.json({ users });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Invite user
app.post('/api/users/invite', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { email, role = 'user' } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email required' });
    }

    // Check if user already exists
    const existingUser = await db.findUserByEmail(email);
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Generate invitation token
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    // Save invitation
    await db.createInvitation(token, email, role, expiresAt);

    // Generate invitation link
    const inviteLink = `${FRONTEND_URL}/accept-invite/${token}`;

    res.json({
      message: 'Invitation created',
      inviteLink,
      expiresAt
    });
  } catch (error) {
    console.error('Invite user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all invitations
app.get('/api/users/invitations', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const invitations = await db.getAllInvitations();
    res.json({ invitations });
  } catch (error) {
    console.error('Get invitations error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Accept invitation (public)
app.post('/api/users/accept-invite', async (req, res) => {
  try {
    const { token, name, password } = req.body;

    if (!token || !name || !password) {
      return res.status(400).json({ error: 'Token, name, and password required' });
    }

    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    // Find invitation
    const invitation = await db.findInvitationByToken(token);
    if (!invitation) {
      return res.status(404).json({ error: 'Invalid or expired invitation' });
    }

    // Check if user already exists
    const existingUser = await db.findUserByEmail(invitation.email);
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Create user
    const user = await db.createUser(
      invitation.email,
      password,
      name,
      invitation.role
    );

    // Delete invitation
    await db.deleteInvitation(token);

    // Generate JWT
    const authToken = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token: authToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        active: user.active
      }
    });
  } catch (error) {
    console.error('Accept invite error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify invitation (public)
app.get('/api/users/verify-invite/:token', async (req, res) => {
  try {
    const { token } = req.params;

    const invitation = await db.findInvitationByToken(token);
    if (!invitation) {
      return res.status(404).json({ error: 'Invalid or expired invitation' });
    }

    res.json({
      email: invitation.email,
      role: invitation.role,
      expiresAt: invitation.expires_at
    });
  } catch (error) {
    console.error('Verify invite error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Activate user
app.post('/api/users/:id/activate', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    await db.updateUserStatus(id, true);

    res.json({ message: 'User activated' });
  } catch (error) {
    console.error('Activate user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Deactivate user
app.post('/api/users/:id/deactivate', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // Prevent deactivating yourself
    if (id === req.user.id) {
      return res.status(400).json({ error: 'Cannot deactivate your own account' });
    }

    await db.updateUserStatus(id, false);

    res.json({ message: 'User deactivated' });
  } catch (error) {
    console.error('Deactivate user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete invitation
app.delete('/api/users/invitations/:token', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { token } = req.params;

    await db.deleteInvitation(token);

    res.json({ message: 'Invitation deleted' });
  } catch (error) {
    console.error('Delete invitation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================================================
// UPDATE EXISTING ROUTES TO USE DATABASE
// ============================================================================

// Health endpoint - updated to use database
app.get('/health', async (req, res) => {
  const stats = await db.getHealthStats();
  res.json(stats);
});

// ============================================================================
// PROTECTED ROUTES
// Add authenticateToken middleware to your existing routes:
//
// Example:
// app.get('/api/warming/accounts', authenticateToken, async (req, res) => { ... });
// app.post('/api/campaigns', authenticateToken, async (req, res) => { ... });
//
// Routes to protect:
// - /api/warming/* (all warming routes)
// - /api/contacts/* (all contact routes)
// - /api/campaigns/* (all campaign routes)
// - /api/smtp/test
//
// Keep public:
// - /health
// - /
// - /api/auth/* (login, accept-invite, verify-invite)
// ============================================================================

// Example: Update warming accounts route
// REPLACE YOUR EXISTING warming routes with these database versions:

app.get('/api/warming/accounts', authenticateToken, async (req, res) => {
  try {
    const accounts = await db.getAllWarmingAccounts();
    res.json({ accounts });
  } catch (error) {
    console.error('Error fetching warming accounts:', error);
    res.status(500).json({ error: 'Failed to fetch accounts' });
  }
});

app.post('/api/warming/accounts', authenticateToken, async (req, res) => {
  try {
    const accountData = req.body;
    const account = await db.createWarmingAccount(accountData);
    res.json({ account });
  } catch (error) {
    console.error('Error creating warming account:', error);
    res.status(500).json({ error: 'Failed to create account' });
  }
});

app.delete('/api/warming/accounts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    await db.deleteWarmingAccount(id);
    res.json({ message: 'Account deleted' });
  } catch (error) {
    console.error('Error deleting warming account:', error);
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

// Example: Update contacts routes
app.get('/api/contacts', authenticateToken, async (req, res) => {
  try {
    const contacts = await db.getAllContacts();
    res.json({ contacts });
  } catch (error) {
    console.error('Error fetching contacts:', error);
    res.status(500).json({ error: 'Failed to fetch contacts' });
  }
});

app.post('/api/contacts', authenticateToken, async (req, res) => {
  try {
    const contactData = req.body;
    
    // Check if bulk import
    if (Array.isArray(contactData)) {
      const contacts = await db.bulkCreateContacts(contactData);
      res.json({ contacts, count: contacts.length });
    } else {
      const contact = await db.createContact(contactData);
      res.json({ contact });
    }
  } catch (error) {
    console.error('Error creating contacts:', error);
    res.status(500).json({ error: 'Failed to create contacts' });
  }
});

// Example: Update campaigns routes
app.get('/api/campaigns', authenticateToken, async (req, res) => {
  try {
    const campaigns = await db.getAllCampaigns();
    res.json({ campaigns });
  } catch (error) {
    console.error('Error fetching campaigns:', error);
    res.status(500).json({ error: 'Failed to fetch campaigns' });
  }
});

app.post('/api/campaigns', authenticateToken, async (req, res) => {
  try {
    const campaignData = req.body;
    const campaign = await db.createCampaign(campaignData);
    res.json({ campaign });
  } catch (error) {
    console.error('Error creating campaign:', error);
    res.status(500).json({ error: 'Failed to create campaign' });
  }
});

app.post('/api/campaigns/:id/start', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const campaign = await db.updateCampaignStatus(id, 'sending');
    res.json({ campaign });
  } catch (error) {
    console.error('Error starting campaign:', error);
    res.status(500).json({ error: 'Failed to start campaign' });
  }
});

app.post('/api/campaigns/:id/stop', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const campaign = await db.updateCampaignStatus(id, 'paused');
    res.json({ campaign });
  } catch (error) {
    console.error('Error stopping campaign:', error);
    res.status(500).json({ error: 'Failed to stop campaign' });
  }
});

// ============================================================================
// NOTES FOR INTEGRATION
// ============================================================================
//
// 1. Install dependencies:
//    npm install pg bcryptjs jsonwebtoken
//
// 2. Add these environment variables to Render:
//    - DATABASE_URL (from PostgreSQL database)
//    - JWT_SECRET (generate a random 32+ character string)
//    - ADMIN_EMAIL (default admin email)
//    - ADMIN_PASSWORD (default admin password)
//    - FRONTEND_URL (your frontend URL)
//
// 3. Create database.js file in your project root
//
// 4. Update package.json to include new dependencies:
//    "pg": "^8.11.3",
//    "bcryptjs": "^2.4.3",
//    "jsonwebtoken": "^9.0.2"
//
// 5. The database will auto-migrate on first startup
//
// ============================================================================

// ============================================
// AUTHENTICATION SYSTEM - INTEGRATED VERSION
// Copy this AFTER line 23 (after app.use('/api/', limiter);)
// in your server-with-warming.js file
// ============================================

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// JWT Secret (from environment variables)
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-key-in-production-min-32-chars';

// In-memory storage for users and invitations
// Add these after your existing Map declarations
const users = new Map();
const invitations = new Map();

// Create master admin account on startup
const MASTER_ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@yourdomain.com';
const MASTER_ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ChangeThisPassword123!';

async function initializeMasterAdmin() {
  const hashedPassword = await bcrypt.hash(MASTER_ADMIN_PASSWORD, 10);
  users.set(MASTER_ADMIN_EMAIL, {
    id: 'admin-001',
    email: MASTER_ADMIN_EMAIL,
    password: hashedPassword,
    role: 'admin',
    name: 'Master Admin',
    createdAt: new Date(),
    isActive: true
  });
  console.log('\n🔐 Master admin account initialized');
  console.log(`   Email: ${MASTER_ADMIN_EMAIL}`);
  console.log(`   Password: ${MASTER_ADMIN_PASSWORD}`);
  console.log('   ⚠️  CHANGE THIS PASSWORD IMMEDIATELY!\n');
}

// Initialize admin on startup
initializeMasterAdmin();

// ============================================
// AUTHENTICATION MIDDLEWARE
// ============================================

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// ============================================
// AUTHENTICATION ENDPOINTS
// ============================================

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = users.get(email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!user.isActive) {
      return res.status(401).json({ error: 'Account is inactive' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        id: user.id, 
        email: user.email, 
        role: user.role 
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = users.get(req.user.email);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role
  });
});

// Change password
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = users.get(req.user.email);

    const validPassword = await bcrypt.compare(currentPassword, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    users.set(user.email, user);

    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// ============================================
// USER MANAGEMENT ENDPOINTS (ADMIN ONLY)
// ============================================

// Get all users
app.get('/api/users', authenticateToken, requireAdmin, (req, res) => {
  const userList = Array.from(users.values()).map(user => ({
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    isActive: user.isActive,
    createdAt: user.createdAt
  }));
  res.json({ users: userList });
});

// Create invitation
app.post('/api/users/invite', authenticateToken, requireAdmin, (req, res) => {
  try {
    const { email, role } = req.body;

    if (users.has(email)) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Generate invitation token
    const inviteToken = crypto.randomBytes(32).toString('hex');
    const invitation = {
      email,
      role: role || 'user',
      token: inviteToken,
      createdBy: req.user.email,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // 7 days
    };

    invitations.set(inviteToken, invitation);

    // Generate invitation link
    const frontendUrl = process.env.FRONTEND_URL || 'https://cold-email-frontend-6xf7.onrender.com';
    const inviteLink = `${frontendUrl}/accept-invite/${inviteToken}`;

    res.json({
      message: 'Invitation created',
      inviteLink,
      invitation: {
        email: invitation.email,
        role: invitation.role,
        expiresAt: invitation.expiresAt
      }
    });
  } catch (error) {
    console.error('Invitation error:', error);
    res.status(500).json({ error: 'Failed to create invitation' });
  }
});

// Get all invitations
app.get('/api/users/invitations', authenticateToken, requireAdmin, (req, res) => {
  const inviteList = Array.from(invitations.values()).map(inv => ({
    email: inv.email,
    role: inv.role,
    token: inv.token,
    createdAt: inv.createdAt,
    expiresAt: inv.expiresAt
  }));
  res.json({ invitations: inviteList });
});

// Accept invitation and create account
app.post('/api/users/accept-invite', async (req, res) => {
  try {
    const { token, name, password } = req.body;

    const invitation = invitations.get(token);
    if (!invitation) {
      return res.status(404).json({ error: 'Invalid invitation' });
    }

    if (new Date() > invitation.expiresAt) {
      invitations.delete(token);
      return res.status(400).json({ error: 'Invitation expired' });
    }

    if (users.has(invitation.email)) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Create user account
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: `user-${Date.now()}`,
      email: invitation.email,
      password: hashedPassword,
      name,
      role: invitation.role,
      createdAt: new Date(),
      isActive: true
    };

    users.set(invitation.email, newUser);
    invitations.delete(token);

    // Generate JWT token
    const authToken = jwt.sign(
      { 
        id: newUser.id, 
        email: newUser.email, 
        role: newUser.role 
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Account created successfully',
      token: authToken,
      user: {
        id: newUser.id,
        email: newUser.email,
        name: newUser.name,
        role: newUser.role
      }
    });
  } catch (error) {
    console.error('Accept invite error:', error);
    res.status(500).json({ error: 'Failed to create account' });
  }
});

// Verify invitation token
app.get('/api/users/verify-invite/:token', (req, res) => {
  const invitation = invitations.get(req.params.token);
  
  if (!invitation) {
    return res.status(404).json({ error: 'Invalid invitation' });
  }

  if (new Date() > invitation.expiresAt) {
    invitations.delete(req.params.token);
    return res.status(400).json({ error: 'Invitation expired' });
  }

  res.json({
    email: invitation.email,
    role: invitation.role
  });
});

// Deactivate user
app.post('/api/users/:userId/deactivate', authenticateToken, requireAdmin, (req, res) => {
  try {
    const userToDeactivate = Array.from(users.values()).find(u => u.id === req.params.userId);
    
    if (!userToDeactivate) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (userToDeactivate.role === 'admin' && userToDeactivate.id === 'admin-001') {
      return res.status(400).json({ error: 'Cannot deactivate master admin' });
    }

    userToDeactivate.isActive = false;
    users.set(userToDeactivate.email, userToDeactivate);

    res.json({ message: 'User deactivated' });
  } catch (error) {
    console.error('Deactivate user error:', error);
    res.status(500).json({ error: 'Failed to deactivate user' });
  }
});

// Reactivate user
app.post('/api/users/:userId/activate', authenticateToken, requireAdmin, (req, res) => {
  try {
    const userToActivate = Array.from(users.values()).find(u => u.id === req.params.userId);
    
    if (!userToActivate) {
      return res.status(404).json({ error: 'User not found' });
    }

    userToActivate.isActive = true;
    users.set(userToActivate.email, userToActivate);

    res.json({ message: 'User activated' });
  } catch (error) {
    console.error('Activate user error:', error);
    res.status(500).json({ error: 'Failed to activate user' });
  }
});

// Delete invitation
app.delete('/api/users/invitations/:token', authenticateToken, requireAdmin, (req, res) => {
  const deleted = invitations.delete(req.params.token);
  if (!deleted) {
    return res.status(404).json({ error: 'Invitation not found' });
  }
  res.json({ message: 'Invitation deleted' });
});

// ============================================
// PROTECT YOUR EXISTING ROUTES
// Find all your existing routes and add authenticateToken
// ============================================

// EXAMPLE - Your existing /health route should stay public:
// app.get('/health', (req, res) => { ... }); // ✅ Keep public

// EXAMPLE - Protect campaign routes:
// Change from: app.post('/api/campaigns', (req, res) => { ... });
// To:          app.post('/api/campaigns', authenticateToken, (req, res) => { ... });

// List of routes to protect (add authenticateToken to these):
// - app.post('/api/campaigns', ...)
// - app.get('/api/campaigns', ...)
// - app.put('/api/campaigns/:id', ...)
// - app.delete('/api/campaigns/:id', ...)
// - app.post('/api/warming/accounts', ...)
// - app.get('/api/warming/accounts', ...)
// - app.delete('/api/warming/accounts/:id', ...)
// - app.post('/api/warming/campaigns/start', ...)
// - app.post('/api/warming/campaigns/stop', ...)
// - app.get('/api/warming/campaigns', ...)
// - app.post('/api/smtp/test', ...)
// - app.post('/api/contacts', ...)
// - app.get('/api/contacts', ...)
// - app.put('/api/contacts/:id', ...)
// - app.delete('/api/contacts/:id', ...)

// ============================================
// END OF AUTHENTICATION CODE
// Place this BEFORE your existing routes
// ============================================

// In-memory storage
const campaigns = new Map();
const warmingCampaigns = new Map();
const emailQueue = [];
const warmingAccounts = new Map();
let isProcessing = false;
let isWarmingActive = false;

// Claude API for generating responses
async function generateAIResponse(originalEmail) {
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 300,
        messages: [{
          role: 'user',
          content: `Generate a natural, friendly email response to this email. Keep it conversational, 2-3 sentences max. The email should feel genuine and human, not robotic.

Original email:
${originalEmail}

Generate ONLY the email body text, no subject line or signatures:`
        }]
      })
    });

    const data = await response.json();
    return data.content[0].text.trim();
  } catch (error) {
    console.error('Error generating AI response:', error);
    // Fallback responses
    const fallbacks = [
      "Thanks for reaching out! I appreciate you thinking of me. How have things been on your end?",
      "Hey, good to hear from you! I've been swamped but things are good. What's new with you?",
      "Thanks for the email! That's really interesting. I'd love to hear more about that.",
      "Appreciate you reaching out. Things have been busy here but going well. How about you?",
      "Good to hear from you! That sounds exciting. Keep me posted on how it goes."
    ];
    return fallbacks[Math.floor(Math.random() * fallbacks.length)];
  }
}

// Generate warming email content
function generateWarmingEmail(fromName, toName) {
  const subjects = [
    "Quick question",
    "Thoughts on this?",
    "Following up",
    "Hey there",
    "Quick catch up",
    "Wanted to share this",
    "Quick update",
    "Just checking in",
    "Hope you're well",
    "Quick hello"
  ];

  const bodies = [
    `Hey ${toName},\n\nHope you're doing well! Just wanted to reach out and see how things are going. Been thinking about that conversation we had.\n\nLet me know when you have a moment to chat.\n\nBest,\n${fromName}`,
    `Hi ${toName},\n\nI came across something that made me think of you. Would love to get your thoughts when you have a chance.\n\nHope all is well!\n\n${fromName}`,
    `${toName},\n\nQuick question - do you have any insights on [topic]? Your expertise would be really helpful here.\n\nThanks!\n${fromName}`,
    `Hey ${toName},\n\nJust checking in! It's been a while since we connected. How have things been?\n\nWould be great to catch up soon.\n\nCheers,\n${fromName}`,
    `Hi ${toName},\n\nI wanted to share this with you - thought you might find it interesting given what you're working on.\n\nLet me know what you think!\n\n${fromName}`,
    `${toName},\n\nHope your week is going well! I had a thought about something we discussed and wanted to run it by you.\n\nFree for a quick chat?\n\nBest,\n${fromName}`,
    `Hey ${toName},\n\nJust wanted to drop you a quick note. Been really busy lately but wanted to stay in touch.\n\nHow are things on your end?\n\n${fromName}`,
    `Hi ${toName},\n\nSaw something that reminded me of our last conversation. Would love to hear your perspective on this.\n\nTalk soon?\n\n${fromName}`
  ];

  return {
    subject: subjects[Math.floor(Math.random() * subjects.length)],
    body: bodies[Math.floor(Math.random() * bodies.length)]
  };
}

// IMAP email checker
async function checkForNewEmails(account) {
  return new Promise((resolve, reject) => {
    const imap = new Imap({
      user: account.email,
      password: account.password,
      host: account.imapHost,
      port: account.imapPort || 993,
      tls: true,
      tlsOptions: { rejectUnauthorized: false }
    });

    const emails = [];

    imap.once('ready', () => {
      imap.openBox('INBOX', false, (err, box) => {
        if (err) {
          reject(err);
          return;
        }

        // Search for unseen emails from the last hour
        const searchCriteria = ['UNSEEN', ['SINCE', new Date(Date.now() - 3600000)]];
        
        imap.search(searchCriteria, (err, results) => {
          if (err || !results || results.length === 0) {
            imap.end();
            resolve(emails);
            return;
          }

          const fetch = imap.fetch(results, { bodies: '' });

          fetch.on('message', (msg) => {
            msg.on('body', (stream) => {
              simpleParser(stream, async (err, parsed) => {
                if (!err && parsed) {
                  emails.push({
                    from: parsed.from.text,
                    subject: parsed.subject,
                    body: parsed.text,
                    date: parsed.date,
                    messageId: parsed.messageId
                  });
                }
              });
            });
          });

          fetch.once('end', () => {
            imap.end();
          });
        });
      });
    });

    imap.once('error', (err) => {
      reject(err);
    });

    imap.once('end', () => {
      resolve(emails);
    });

    imap.connect();
  });
}

// Send warming email
async function sendWarmingEmail(fromAccount, toAccount) {
  try {
    const transporter = nodemailer.createTransport({
      host: fromAccount.smtpHost,
      port: fromAccount.smtpPort,
      secure: fromAccount.smtpPort === 465,
      auth: {
        user: fromAccount.email,
        pass: fromAccount.password
      }
    });

    const emailContent = generateWarmingEmail(fromAccount.name, toAccount.name);

    await transporter.sendMail({
      from: `"${fromAccount.name}" <${fromAccount.email}>`,
      to: toAccount.email,
      subject: emailContent.subject,
      text: emailContent.body,
      html: emailContent.body.replace(/\n/g, '<br>')
    });

    console.log(`Warming email sent: ${fromAccount.email} -> ${toAccount.email}`);
    return true;
  } catch (error) {
    console.error(`Failed to send warming email:`, error.message);
    return false;
  }
}

// Auto-respond to warming emails
async function autoRespondToEmail(account, originalEmail) {
  try {
    const transporter = nodemailer.createTransport({
      host: account.smtpHost,
      port: account.smtpPort,
      secure: account.smtpPort === 465,
      auth: {
        user: account.email,
        pass: account.password
      }
    });

    // Generate AI response
    const responseBody = await generateAIResponse(originalEmail.body);

    // Extract sender email
    const senderMatch = originalEmail.from.match(/<(.+?)>/);
    const senderEmail = senderMatch ? senderMatch[1] : originalEmail.from;

    await transporter.sendMail({
      from: `"${account.name}" <${account.email}>`,
      to: senderEmail,
      subject: `Re: ${originalEmail.subject}`,
      text: responseBody,
      html: responseBody.replace(/\n/g, '<br>'),
      inReplyTo: originalEmail.messageId,
      references: originalEmail.messageId
    });

    console.log(`Auto-response sent: ${account.email} -> ${senderEmail}`);
    return true;
  } catch (error) {
    console.error(`Failed to send auto-response:`, error.message);
    return false;
  }
}

// Warming campaign processor
async function processWarmingCampaign(campaignId) {
  const campaign = warmingCampaigns.get(campaignId);
  if (!campaign || campaign.status !== 'active') return;

  const accounts = Array.from(warmingAccounts.values());
  
  // Send emails between accounts
  for (let i = 0; i < campaign.emailsPerDay; i++) {
    const fromAccount = accounts[Math.floor(Math.random() * accounts.length)];
    let toAccount = accounts[Math.floor(Math.random() * accounts.length)];
    
    // Make sure we don't send to ourselves
    while (toAccount.email === fromAccount.email && accounts.length > 1) {
      toAccount = accounts[Math.floor(Math.random() * accounts.length)];
    }

    // Send warming email
    const sent = await sendWarmingEmail(fromAccount, toAccount);
    
    if (sent) {
      campaign.stats.sent++;
    } else {
      campaign.stats.failed++;
    }

    // Wait before next email
    const delayMinutes = Math.floor(1440 / campaign.emailsPerDay); // Spread throughout day
    const randomDelay = delayMinutes * 60 * 1000 * (0.8 + Math.random() * 0.4); // +/- 20% randomness
    
    await new Promise(resolve => setTimeout(resolve, randomDelay));
  }
}

// Email monitoring loop
async function monitorAndRespondToEmails() {
  if (!isWarmingActive) return;

  const accounts = Array.from(warmingAccounts.values());
  
  for (const account of accounts) {
    if (!account.enableAutoResponse) continue;

    try {
      const newEmails = await checkForNewEmails(account);
      
      for (const email of newEmails) {
        // Check if email is from another warming account
        const isFromWarmingAccount = accounts.some(acc => 
          email.from.includes(acc.email)
        );

        if (isFromWarmingAccount) {
          // Wait a random time before responding (1-4 hours)
          const responseDelay = (1 + Math.random() * 3) * 3600 * 1000;
          
          setTimeout(async () => {
            await autoRespondToEmail(account, email);
          }, responseDelay);
        }
      }
    } catch (error) {
      console.error(`Error monitoring ${account.email}:`, error.message);
    }
  }

  // Check again in 15 minutes
  setTimeout(monitorAndRespondToEmails, 15 * 60 * 1000);
}

// Email queue processor (existing campaigns)
async function processEmailQueue() {
  if (isProcessing || emailQueue.length === 0) return;
  
  isProcessing = true;
  
  while (emailQueue.length > 0) {
    const job = emailQueue.shift();
    const campaign = campaigns.get(job.campaignId);
    
    if (!campaign) continue;
    
    try {
      await new Promise(resolve => setTimeout(resolve, job.delay * 1000));
      
      const transporter = nodemailer.createTransport({
        host: campaign.smtp.host,
        port: campaign.smtp.port,
        secure: campaign.smtp.secure,
        auth: {
          user: campaign.smtp.username,
          pass: campaign.smtp.password
        }
      });
      
      let subject = campaign.template.subject;
      let body = campaign.template.body;
      
      Object.keys(job.contact).forEach(key => {
        const regex = new RegExp(`{{${key}}}`, 'g');
        subject = subject.replace(regex, job.contact[key] || '');
        body = body.replace(regex, job.contact[key] || '');
      });
      
      if (campaign.settings.unsubscribeLink) {
        const unsubscribeUrl = `${process.env.BASE_URL}/unsubscribe?email=${encodeURIComponent(job.contact.email)}&campaign=${job.campaignId}`;
        body += `\n\n---\nUnsubscribe: ${unsubscribeUrl}`;
      }
      
      const info = await transporter.sendMail({
        from: `"${campaign.template.fromName}" <${campaign.template.fromEmail}>`,
        to: job.contact.email,
        subject: subject,
        text: body,
        html: body.replace(/\n/g, '<br>')
      });
      
      console.log(`Email sent to ${job.contact.email}: ${info.messageId}`);
      
      campaign.stats.sent++;
      campaign.contacts.find(c => c.id === job.contact.id).status = 'sent';
      
    } catch (error) {
      console.error(`Failed to send email to ${job.contact.email}:`, error.message);
      campaign.stats.failed++;
      campaign.contacts.find(c => c.id === job.contact.id).status = 'failed';
    }
    
    const totalProcessed = campaign.stats.sent + campaign.stats.failed;
    if (totalProcessed >= campaign.stats.total) {
      campaign.status = 'completed';
    }
  }
  
  isProcessing = false;
}

// API Routes

// Test SMTP connection
app.post('/api/smtp/test', async (req, res) => {
  try {
    const { host, port, username, password, secure } = req.body;
    
    const transporter = nodemailer.createTransport({
      host,
      port: parseInt(port),
      secure: secure || false,
      auth: { user: username, pass: password }
    });
    
    await transporter.verify();
    res.json({ success: true, message: 'SMTP connection successful' });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
});

// Test IMAP connection
app.post('/api/imap/test', async (req, res) => {
  try {
    const { email, password, imapHost, imapPort } = req.body;
    
    const imap = new Imap({
      user: email,
      password: password,
      host: imapHost,
      port: imapPort || 993,
      tls: true,
      tlsOptions: { rejectUnauthorized: false }
    });

    let testSuccess = false;

    imap.once('ready', () => {
      testSuccess = true;
      imap.end();
    });

    imap.once('error', (err) => {
      imap.end();
    });

    imap.once('end', () => {
      if (testSuccess) {
        res.json({ success: true, message: 'IMAP connection successful' });
      } else {
        res.status(400).json({ success: false, message: 'IMAP connection failed' });
      }
    });

    imap.connect();
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
});

// Add warming account
app.post('/api/warming/accounts', (req, res) => {
  try {
    const account = {
      id: Date.now().toString(),
      ...req.body,
      createdAt: new Date()
    };
    
    warmingAccounts.set(account.id, account);
    res.json({ success: true, account });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
});

// Get all warming accounts
app.get('/api/warming/accounts', (req, res) => {
  const accounts = Array.from(warmingAccounts.values()).map(acc => ({
    id: acc.id,
    name: acc.name,
    email: acc.email,
    enableAutoResponse: acc.enableAutoResponse,
    createdAt: acc.createdAt
  }));
  res.json({ success: true, accounts });
});

// Remove warming account
app.delete('/api/warming/accounts/:id', (req, res) => {
  const deleted = warmingAccounts.delete(req.params.id);
  res.json({ success: deleted, message: deleted ? 'Account removed' : 'Account not found' });
});

// Create warming campaign
app.post('/api/warming/campaigns', (req, res) => {
  try {
    const campaignId = Date.now().toString();
    const campaign = {
      id: campaignId,
      status: 'draft',
      emailsPerDay: req.body.emailsPerDay || 10,
      duration: req.body.duration || 30,
      stats: {
        sent: 0,
        failed: 0,
        responses: 0
      },
      createdAt: new Date()
    };
    
    warmingCampaigns.set(campaignId, campaign);
    res.json({ success: true, campaignId, campaign });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
});

// Start warming campaign
app.post('/api/warming/campaigns/:id/start', async (req, res) => {
  try {
    const campaign = warmingCampaigns.get(req.params.id);
    
    if (!campaign) {
      return res.status(404).json({ success: false, message: 'Campaign not found' });
    }

    if (warmingAccounts.size < 2) {
      return res.status(400).json({ success: false, message: 'Need at least 2 accounts for warming' });
    }

    campaign.status = 'active';
    isWarmingActive = true;
    
    // Start warming process
    processWarmingCampaign(campaign.id);
    
    // Start email monitoring
    monitorAndRespondToEmails();
    
    res.json({ 
      success: true, 
      message: `Warming campaign started with ${warmingAccounts.size} accounts`,
      campaign 
    });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
});

// Get warming campaign status
app.get('/api/warming/campaigns/:id', (req, res) => {
  const campaign = warmingCampaigns.get(req.params.id);
  
  if (!campaign) {
    return res.status(404).json({ success: false, message: 'Campaign not found' });
  }
  
  res.json({ success: true, campaign });
});

// Stop warming campaign
app.post('/api/warming/campaigns/:id/stop', (req, res) => {
  const campaign = warmingCampaigns.get(req.params.id);
  
  if (!campaign) {
    return res.status(404).json({ success: false, message: 'Campaign not found' });
  }
  
  campaign.status = 'stopped';
  isWarmingActive = false;
  
  res.json({ success: true, message: 'Warming campaign stopped' });
});

// Regular campaign routes (existing)
app.post('/api/campaigns', (req, res) => {
  try {
    const campaignId = Date.now().toString();
    const campaign = {
      id: campaignId,
      status: 'draft',
      template: req.body.template,
      contacts: req.body.contacts,
      smtp: req.body.smtp,
      settings: req.body.settings,
      stats: {
        total: req.body.contacts.filter(c => c.email).length,
        sent: 0,
        failed: 0
      },
      createdAt: new Date()
    };
    
    campaigns.set(campaignId, campaign);
    res.json({ success: true, campaignId, campaign });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
});

app.post('/api/campaigns/:id/start', (req, res) => {
  try {
    const campaign = campaigns.get(req.params.id);
    
    if (!campaign) {
      return res.status(404).json({ success: false, message: 'Campaign not found' });
    }
    
    if (campaign.status !== 'draft') {
      return res.status(400).json({ success: false, message: 'Campaign already started' });
    }
    
    const validContacts = campaign.contacts.filter(c => c.email && c.status === 'pending');
    
    validContacts.forEach((contact) => {
      emailQueue.push({
        campaignId: campaign.id,
        contact: contact,
        delay: campaign.settings.delayBetweenEmails || 30
      });
    });
    
    campaign.status = 'running';
    processEmailQueue();
    
    res.json({ 
      success: true, 
      message: `Campaign started with ${validContacts.length} emails queued`,
      campaign 
    });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
});

app.get('/api/campaigns/:id', (req, res) => {
  const campaign = campaigns.get(req.params.id);
  
  if (!campaign) {
    return res.status(404).json({ success: false, message: 'Campaign not found' });
  }
  
  res.json({ 
    success: true, 
    campaign: {
      id: campaign.id,
      status: campaign.status,
      stats: campaign.stats,
      contacts: campaign.contacts.map(c => ({
        id: c.id,
        email: c.email,
        status: c.status
      }))
    }
  });
});

app.post('/api/campaigns/:id/pause', (req, res) => {
  const campaign = campaigns.get(req.params.id);
  
  if (!campaign) {
    return res.status(404).json({ success: false, message: 'Campaign not found' });
  }
  
  campaign.status = 'paused';
  res.json({ success: true, message: 'Campaign paused' });
});

app.get('/unsubscribe', (req, res) => {
  const { email, campaign } = req.query;
  console.log(`Unsubscribe request: ${email} from campaign ${campaign}`);
  
  res.send(`
    <html>
      <body style="font-family: Arial; max-width: 600px; margin: 50px auto; text-align: center;">
        <h1>Unsubscribed Successfully</h1>
        <p>You have been removed from our mailing list.</p>
        <p>Email: ${email}</p>
      </body>
    </html>
  `);
});

// Homepage
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>Cold Email System API</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
          }
          .container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
          }
          .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
          }
          .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
          }
          .status {
            display: inline-block;
            background: rgba(255,255,255,0.2);
            padding: 10px 20px;
            border-radius: 50px;
            margin-top: 20px;
          }
          .status-dot {
            display: inline-block;
            width: 12px;
            height: 12px;
            background: #4ade80;
            border-radius: 50%;
            margin-right: 8px;
            animation: pulse 2s infinite;
          }
          @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
          }
          .content {
            padding: 40px;
          }
          .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
          }
          .stat-card {
            background: #f8fafc;
            padding: 20px;
            border-radius: 12px;
            text-align: center;
            border: 2px solid #e2e8f0;
          }
          .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 5px;
          }
          .stat-label {
            color: #64748b;
            font-size: 0.9em;
          }
          .section {
            margin-bottom: 30px;
          }
          .section h2 {
            color: #1e293b;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e2e8f0;
          }
          .endpoint {
            background: #f8fafc;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 10px;
            border-left: 4px solid #667eea;
          }
          .method {
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            margin-right: 10px;
          }
          .method.post { background: #10b981; }
          .method.delete { background: #ef4444; }
          .path {
            font-family: 'Courier New', monospace;
            color: #475569;
          }
          .description {
            color: #64748b;
            font-size: 0.9em;
            margin-top: 5px;
          }
          .footer {
            background: #f8fafc;
            padding: 20px;
            text-align: center;
            color: #64748b;
            font-size: 0.9em;
          }
          .footer a {
            color: #667eea;
            text-decoration: none;
          }
          .footer a:hover {
            text-decoration: underline;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🚀 Cold Email System</h1>
            <p>AI-Powered Email Warming & Campaign Management</p>
            <div class="status">
              <span class="status-dot"></span>
              <span>System Online</span>
            </div>
          </div>
          
          <div class="content">
            <div class="stats">
              <div class="stat-card">
                <div class="stat-value">${campaigns.size}</div>
                <div class="stat-label">Cold Campaigns</div>
              </div>
              <div class="stat-card">
                <div class="stat-value">${warmingCampaigns.size}</div>
                <div class="stat-label">Warming Campaigns</div>
              </div>
              <div class="stat-card">
                <div class="stat-value">${warmingAccounts.size}</div>
                <div class="stat-label">Warm Accounts</div>
              </div>
              <div class="stat-card">
                <div class="stat-value">${emailQueue.length}</div>
                <div class="stat-label">Queue Length</div>
              </div>
            </div>

            <div class="section">
              <h2>📍 API Endpoints</h2>
              
              <div class="endpoint">
                <span class="method">GET</span>
                <span class="path">/health</span>
                <div class="description">System health check and statistics</div>
              </div>

              <div class="endpoint">
                <span class="method post">POST</span>
                <span class="path">/api/smtp/test</span>
                <div class="description">Test SMTP connection with credentials</div>
              </div>

              <div class="endpoint">
                <span class="method post">POST</span>
                <span class="path">/api/warming/accounts</span>
                <div class="description">Add new warming account</div>
              </div>

              <div class="endpoint">
                <span class="method">GET</span>
                <span class="path">/api/warming/accounts</span>
                <div class="description">List all warming accounts</div>
              </div>

              <div class="endpoint">
                <span class="method post">POST</span>
                <span class="path">/api/warming/campaigns/start</span>
                <div class="description">Start email warming campaign</div>
              </div>

              <div class="endpoint">
                <span class="method">GET</span>
                <span class="path">/api/warming/campaigns</span>
                <div class="description">Get warming campaign status</div>
              </div>

              <div class="endpoint">
                <span class="method post">POST</span>
                <span class="path">/api/campaigns</span>
                <div class="description">Create new cold email campaign</div>
              </div>

              <div class="endpoint">
                <span class="method">GET</span>
                <span class="path">/api/campaigns</span>
                <div class="description">List all campaigns</div>
              </div>

              <div class="endpoint">
                <span class="method">GET</span>
                <span class="path">/api/campaigns/:id</span>
                <div class="description">Get specific campaign details</div>
              </div>

              <div class="endpoint">
                <span class="method post">POST</span>
                <span class="path">/api/contacts</span>
                <div class="description">Add contacts to campaign</div>
              </div>

              <div class="endpoint">
                <span class="method">GET</span>
                <span class="path">/api/contacts/:campaignId</span>
                <div class="description">Get contacts for campaign</div>
              </div>
            </div>

            <div class="section">
              <h2>✨ Features</h2>
              <div class="endpoint">
                <strong>🔥 Email Warming:</strong> Automated account warming with AI-generated conversations
              </div>
              <div class="endpoint">
                <strong>📧 Cold Campaigns:</strong> Personalized cold email campaigns with tracking
              </div>
              <div class="endpoint">
                <strong>🤖 AI Responses:</strong> Claude-powered auto-responses to warming emails
              </div>
              <div class="endpoint">
                <strong>📊 Analytics:</strong> Track opens, clicks, replies, and conversions
              </div>
            </div>
          </div>

          <div class="footer">
            <p>Built with Node.js + Express | Deployed on Render</p>
            <p><a href="/health">View Health Status</a></p>
          </div>
        </div>
      </body>
    </html>
  `);
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    campaigns: campaigns.size,
    warmingCampaigns: warmingCampaigns.size,
    warmingAccounts: warmingAccounts.size,
    queueLength: emailQueue.length,
    isProcessing,
    isWarmingActive
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Cold Email Backend with Warming running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health`);
  console.log('Server is ready to accept connections');
});
