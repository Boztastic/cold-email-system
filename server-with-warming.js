// ============================================================================
// COLD EMAIL SYSTEM - COMPLETE SERVER WITH POSTGRESQL AUTHENTICATION
// Includes: Authentication, User Management, Warming, Campaigns, Contacts
// ============================================================================

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const Imap = require('imap');
const { simpleParser } = require('mailparser');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 10000;

// ============================================================================
// MIDDLEWARE
// ============================================================================

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use('/api/', limiter);

// ============================================================================
// AUTHENTICATION CONFIGURATION
// ============================================================================

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// Run database migrations on startup
db.runMigrations().catch(err => {
  console.error('Failed to run migrations:', err);
  process.exit(1);
});

// ============================================================================
// AUTHENTICATION MIDDLEWARE
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
// PUBLIC ROUTES
// ============================================================================

// Health check
app.get('/health', async (req, res) => {
  const stats = await db.getHealthStats();
  res.json(stats);
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Cold Email System API',
    version: '2.0.0',
    status: 'online',
    endpoints: {
      health: '/health',
      auth: {
        login: 'POST /api/auth/login',
        me: 'GET /api/auth/me (authenticated)',
        changePassword: 'POST /api/auth/change-password (authenticated)'
      },
      users: {
        list: 'GET /api/users (admin)',
        invite: 'POST /api/users/invite (admin)',
        invitations: 'GET /api/users/invitations (admin)',
        acceptInvite: 'POST /api/users/accept-invite (public)',
        verifyInvite: 'GET /api/users/verify-invite/:token (public)'
      },
      warming: {
        accounts: 'GET /api/warming/accounts (authenticated)',
        addAccount: 'POST /api/warming/accounts (authenticated)',
        deleteAccount: 'DELETE /api/warming/accounts/:id (authenticated)'
      },
      contacts: {
        list: 'GET /api/contacts (authenticated)',
        create: 'POST /api/contacts (authenticated)'
      },
      campaigns: {
        list: 'GET /api/campaigns (authenticated)',
        create: 'POST /api/campaigns (authenticated)',
        start: 'POST /api/campaigns/:id/start (authenticated)',
        stop: 'POST /api/campaigns/:id/stop (authenticated)'
      }
    }
  });
});

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
// WARMING ROUTES (Protected)
// ============================================================================

// Get all warming accounts
app.get('/api/warming/accounts', authenticateToken, async (req, res) => {
  try {
    const accounts = await db.getAllWarmingAccounts();
    res.json({ accounts });
  } catch (error) {
    console.error('Error fetching warming accounts:', error);
    res.status(500).json({ error: 'Failed to fetch accounts' });
  }
});

// Add warming account
app.post('/api/warming/accounts', authenticateToken, async (req, res) => {
  try {
    const accountData = req.body;
    
    // Validate required fields
    if (!accountData.email || !accountData.smtp_host || !accountData.smtp_port || 
        !accountData.smtp_user || !accountData.smtp_pass || !accountData.imap_host || 
        !accountData.imap_port) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const account = await db.createWarmingAccount(accountData);
    res.json({ account, message: 'Warming account added successfully' });
  } catch (error) {
    console.error('Error creating warming account:', error);
    res.status(500).json({ error: 'Failed to create account' });
  }
});

// Delete warming account
app.delete('/api/warming/accounts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    await db.deleteWarmingAccount(id);
    res.json({ message: 'Account deleted successfully' });
  } catch (error) {
    console.error('Error deleting warming account:', error);
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

// Test SMTP connection
app.post('/api/smtp/test', authenticateToken, async (req, res) => {
  try {
    const { smtp_host, smtp_port, smtp_user, smtp_pass } = req.body;

    const transporter = nodemailer.createTransport({
      host: smtp_host,
      port: smtp_port,
      secure: smtp_port === 465,
      auth: {
        user: smtp_user,
        pass: smtp_pass
      }
    });

    await transporter.verify();
    res.json({ success: true, message: 'SMTP connection successful' });
  } catch (error) {
    console.error('SMTP test error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// CONTACTS ROUTES (Protected)
// ============================================================================

// Get all contacts
app.get('/api/contacts', authenticateToken, async (req, res) => {
  try {
    const contacts = await db.getAllContacts();
    res.json({ contacts });
  } catch (error) {
    console.error('Error fetching contacts:', error);
    res.status(500).json({ error: 'Failed to fetch contacts' });
  }
});

// Create contact(s)
app.post('/api/contacts', authenticateToken, async (req, res) => {
  try {
    const contactData = req.body;
    
    // Check if bulk import
    if (Array.isArray(contactData)) {
      const contacts = await db.bulkCreateContacts(contactData);
      res.json({ contacts, count: contacts.length, message: `${contacts.length} contacts imported` });
    } else {
      // Single contact
      if (!contactData.email) {
        return res.status(400).json({ error: 'Email is required' });
      }
      const contact = await db.createContact(contactData);
      res.json({ contact, message: 'Contact created successfully' });
    }
  } catch (error) {
    console.error('Error creating contacts:', error);
    res.status(500).json({ error: 'Failed to create contacts' });
  }
});

// ============================================================================
// CAMPAIGNS ROUTES (Protected)
// ============================================================================

// Get all campaigns
app.get('/api/campaigns', authenticateToken, async (req, res) => {
  try {
    const campaigns = await db.getAllCampaigns();
    res.json({ campaigns });
  } catch (error) {
    console.error('Error fetching campaigns:', error);
    res.status(500).json({ error: 'Failed to fetch campaigns' });
  }
});

// Create campaign
app.post('/api/campaigns', authenticateToken, async (req, res) => {
  try {
    const campaignData = req.body;
    
    // Validate required fields
    if (!campaignData.name || !campaignData.subject || !campaignData.body || 
        !campaignData.from_name || !campaignData.from_email) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const campaign = await db.createCampaign(campaignData);
    res.json({ campaign, message: 'Campaign created successfully' });
  } catch (error) {
    console.error('Error creating campaign:', error);
    res.status(500).json({ error: 'Failed to create campaign' });
  }
});

// Start campaign
app.post('/api/campaigns/:id/start', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const campaign = await db.updateCampaignStatus(id, 'sending');
    res.json({ campaign, message: 'Campaign started' });
  } catch (error) {
    console.error('Error starting campaign:', error);
    res.status(500).json({ error: 'Failed to start campaign' });
  }
});

// Stop campaign
app.post('/api/campaigns/:id/stop', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const campaign = await db.updateCampaignStatus(id, 'paused');
    res.json({ campaign, message: 'Campaign stopped' });
  } catch (error) {
    console.error('Error stopping campaign:', error);
    res.status(500).json({ error: 'Failed to stop campaign' });
  }
});

// ============================================================================
// EMAIL WARMING LOGIC
// ============================================================================

// Helper function to send warming email
async function sendWarmingEmail(account, recipientEmail) {
  const transporter = nodemailer.createTransport({
    host: account.smtp_host,
    port: account.smtp_port,
    secure: account.smtp_port === 465,
    auth: {
      user: account.smtp_user,
      pass: account.smtp_pass
    }
  });

  const subjects = [
    'Quick question',
    'Following up',
    'Checking in',
    'Hope you\'re well',
    'Quick hello'
  ];

  const bodies = [
    'Hi,\n\nJust wanted to check in and see how things are going.\n\nBest regards',
    'Hello,\n\nHope this email finds you well. Looking forward to connecting.\n\nThanks',
    'Hi there,\n\nJust a quick message to stay in touch.\n\nCheers',
    'Hello,\n\nHope you\'re having a great day!\n\nBest',
    'Hi,\n\nJust reaching out to say hello.\n\nTake care'
  ];

  const subject = subjects[Math.floor(Math.random() * subjects.length)];
  const body = bodies[Math.floor(Math.random() * bodies.length)];

  await transporter.sendMail({
    from: `"${account.email.split('@')[0]}" <${account.email}>`,
    to: recipientEmail,
    subject: subject,
    text: body
  });
}

// Start warming campaign (can be triggered manually or by scheduler)
app.post('/api/warming/start', authenticateToken, async (req, res) => {
  try {
    const accounts = await db.getAllWarmingAccounts();
    const activeAccounts = accounts.filter(acc => acc.status === 'active');

    if (activeAccounts.length === 0) {
      return res.json({ message: 'No active warming accounts' });
    }

    let totalSent = 0;

    for (const account of activeAccounts) {
      try {
        // Simple warming logic: send emails to other warming accounts
        const otherAccounts = activeAccounts.filter(acc => acc.email !== account.email);
        
        if (otherAccounts.length > 0) {
          const recipient = otherAccounts[Math.floor(Math.random() * otherAccounts.length)];
          await sendWarmingEmail(account, recipient.email);
          totalSent++;
        }
      } catch (error) {
        console.error(`Error warming account ${account.email}:`, error);
      }
    }

    res.json({ 
      message: `Warming round completed`, 
      emailsSent: totalSent,
      accountsProcessed: activeAccounts.length
    });
  } catch (error) {
    console.error('Error in warming process:', error);
    res.status(500).json({ error: 'Warming process failed' });
  }
});

// ============================================================================
// ERROR HANDLING
// ============================================================================

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ============================================================================
// START SERVER
// ============================================================================

app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║  🚀 Cold Email System - Server Started                        ║
║                                                                ║
║  Port: ${PORT}                                                    ║
║  Environment: ${process.env.NODE_ENV || 'development'}                                        ║
║  Database: ${process.env.DATABASE_URL ? '✅ Connected' : '❌ Not configured'}                              ║
║                                                                ║
║  Authentication: ✅ Enabled                                    ║
║  API Endpoints: /health, /api/auth, /api/users, /api/warming  ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
  `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing server gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, closing server gracefully...');
  process.exit(0);
});
