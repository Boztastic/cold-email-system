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
