// ============================================================================
// COLD EMAIL SYSTEM - COMPLETE SERVER WITH ALL FEATURES
// Email Sending Engine, Tracking, Sequences, Templates, Analytics
// ============================================================================

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 10000;

// ============================================================================
// CONFIGURATION
// ============================================================================

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
const BACKEND_URL = process.env.BACKEND_URL || `http://localhost:${PORT}`;

// ============================================================================
// MIDDLEWARE
// ============================================================================

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200
});
app.use('/api/', limiter);

// ============================================================================
// DATABASE INITIALIZATION
// ============================================================================

db.runMigrations().catch(err => {
  console.error('Failed to run migrations:', err);
  process.exit(1);
});

// ============================================================================
// AUTHENTICATION MIDDLEWARE
// ============================================================================

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await db.findUserById(decoded.userId);
    
    if (!user || !user.active) {
      return res.status(401).json({ error: 'Invalid or inactive user' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// ============================================================================
// EMAIL SENDING ENGINE
// ============================================================================

// Personalize email content with contact data
function personalizeContent(template, contact) {
  let content = template;
  content = content.replace(/\{\{first_name\}\}/gi, contact.first_name || '');
  content = content.replace(/\{\{last_name\}\}/gi, contact.last_name || '');
  content = content.replace(/\{\{company\}\}/gi, contact.company || '');
  content = content.replace(/\{\{title\}\}/gi, contact.title || '');
  content = content.replace(/\{\{email\}\}/gi, contact.email || '');
  content = content.replace(/\{\{name\}\}/gi, 
    (contact.first_name || '') + (contact.last_name ? ' ' + contact.last_name : '') || 'there'
  );
  return content.trim();
}

// Add tracking pixel to email body
function addTrackingPixel(body, trackingId) {
  const pixelUrl = `${BACKEND_URL}/track/open/${trackingId}`;
  const pixel = `<img src="${pixelUrl}" width="1" height="1" style="display:none" alt="" />`;
  
  // If HTML, add before closing body tag
  if (body.includes('</body>')) {
    return body.replace('</body>', `${pixel}</body>`);
  }
  
  // Otherwise add at the end
  return body + `<br/>${pixel}`;
}

// Wrap links for click tracking
function wrapLinksForTracking(body, trackingId) {
  const linkRegex = /href=["'](https?:\/\/[^"']+)["']/gi;
  
  return body.replace(linkRegex, (match, url) => {
    // Don't wrap unsubscribe links
    if (url.includes('unsubscribe')) return match;
    
    const encodedUrl = encodeURIComponent(url);
    const trackingUrl = `${BACKEND_URL}/track/click/${trackingId}?url=${encodedUrl}`;
    return `href="${trackingUrl}"`;
  });
}

// Add unsubscribe link to email
function addUnsubscribeLink(body, email) {
  const unsubscribeUrl = `${BACKEND_URL}/unsubscribe?email=${encodeURIComponent(email)}`;
  const unsubscribeHtml = `
    <br/><br/>
    <div style="text-align:center;font-size:12px;color:#666;margin-top:20px;padding-top:20px;border-top:1px solid #eee;">
      <a href="${unsubscribeUrl}" style="color:#666;">Unsubscribe</a> from future emails
    </div>
  `;
  
  if (body.includes('</body>')) {
    return body.replace('</body>', `${unsubscribeHtml}</body>`);
  }
  
  return body + unsubscribeHtml;
}

// Send a single email
async function sendEmail(queueItem) {
  try {
    // Get an available warming account
    const account = await db.getActiveWarmingAccount();
    if (!account) {
      throw new Error('No available sending accounts');
    }

    // Create transporter
    const transporter = nodemailer.createTransport({
      host: account.smtp_host,
      port: account.smtp_port,
      secure: account.smtp_port === 465,
      auth: {
        user: account.smtp_user,
        pass: account.smtp_pass
      }
    });

    // Get contact for personalization
    const contact = await db.getContactById(queueItem.contact_id);
    if (!contact) {
      throw new Error('Contact not found');
    }

    // Check if unsubscribed
    if (await db.isUnsubscribed(contact.email)) {
      throw new Error('Contact is unsubscribed');
    }

    // Personalize content
    let subject = personalizeContent(queueItem.subject, contact);
    let body = personalizeContent(queueItem.body, contact);

    // Create tracking record
    const tracking = await db.createTracking({
      campaign_id: queueItem.campaign_id,
      sequence_id: queueItem.sequence_id,
      sequence_step_id: queueItem.sequence_step_id,
      contact_id: queueItem.contact_id,
      email_queue_id: queueItem.id
    });

    // Add tracking to email
    body = addTrackingPixel(body, tracking.tracking_id);
    body = wrapLinksForTracking(body, tracking.tracking_id);
    body = addUnsubscribeLink(body, contact.email);

    // Send email
    await transporter.sendMail({
      from: `"${queueItem.from_name}" <${account.email}>`,
      replyTo: queueItem.from_email,
      to: contact.email,
      subject: subject,
      html: body
    });

    // Update records
    await db.updateQueueItemStatus(queueItem.id, 'sent');
    await db.updateWarmingAccountUsage(account.id);
    await db.updateDailyStats('emails_sent');

    if (queueItem.campaign_id) {
      await db.updateCampaignStats(queueItem.campaign_id, 'emails_sent');
    }

    console.log(`✉️ Email sent to ${contact.email}`);
    return { success: true, trackingId: tracking.tracking_id };

  } catch (error) {
    console.error('Send email error:', error.message);
    await db.updateQueueItemStatus(queueItem.id, 'failed', error.message);
    return { success: false, error: error.message };
  }
}

// Process email queue
async function processEmailQueue() {
  try {
    const queueItems = await db.getNextQueuedEmails(5);
    
    for (const item of queueItems) {
      await sendEmail(item);
      // Rate limiting: wait between sends
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
    
    return queueItems.length;
  } catch (error) {
    console.error('Queue processing error:', error);
    return 0;
  }
}

// Process sequence emails
async function processSequenceEmails() {
  try {
    const dueContacts = await db.getSequenceContactsDueForEmail();
    
    for (const sc of dueContacts) {
      // Add to queue
      await db.addToEmailQueue({
        sequence_id: sc.sequence_id,
        sequence_step_id: sc.id,
        contact_id: sc.contact_id,
        to_email: sc.email,
        to_name: `${sc.first_name || ''} ${sc.last_name || ''}`.trim(),
        from_email: sc.from_email,
        from_name: sc.from_name,
        subject: personalizeContent(sc.subject, sc),
        body: personalizeContent(sc.body, sc),
        priority: 3
      });

      // Get next step info
      const sequence = await db.getSequenceWithSteps(sc.sequence_id);
      const currentStepIndex = sequence.steps.findIndex(s => s.step_number === sc.current_step);
      const nextStep = sequence.steps[currentStepIndex + 1];

      if (nextStep) {
        // Calculate next email time
        const nextEmailAt = new Date();
        nextEmailAt.setDate(nextEmailAt.getDate() + nextStep.delay_days);
        nextEmailAt.setHours(nextEmailAt.getHours() + nextStep.delay_hours);
        
        await db.updateSequenceContactAfterSend(sc.id, nextStep.step_number, nextEmailAt);
      } else {
        // Sequence completed for this contact
        await db.updateSequenceContactAfterSend(sc.id, null, null);
      }
    }
    
    return dueContacts.length;
  } catch (error) {
    console.error('Sequence processing error:', error);
    return 0;
  }
}

// Background job scheduler
let emailJobInterval;
function startEmailProcessor() {
  console.log('📧 Starting email processor...');
  
  // Process queue every 10 seconds
  emailJobInterval = setInterval(async () => {
    await processEmailQueue();
    await processSequenceEmails();
  }, 10000);
  
  // Reset daily counts at midnight
  const resetDaily = () => {
    const now = new Date();
    const tomorrow = new Date(now);
    tomorrow.setDate(tomorrow.getDate() + 1);
    tomorrow.setHours(0, 0, 0, 0);
    
    const msUntilMidnight = tomorrow - now;
    
    setTimeout(async () => {
      await db.resetDailyWarmingCounts();
      console.log('🔄 Daily warming counts reset');
      resetDaily(); // Schedule next reset
    }, msUntilMidnight);
  };
  
  resetDaily();
}

// ============================================================================
// PUBLIC ROUTES
// ============================================================================

// Health check
app.get('/health', async (req, res) => {
  const stats = await db.getHealthStats();
  res.json(stats);
});

// Root
app.get('/', (req, res) => {
  res.json({
    message: 'Cold Email System API v2.0',
    status: 'online',
    features: ['authentication', 'campaigns', 'sequences', 'templates', 'tracking', 'analytics']
  });
});

// ============================================================================
// TRACKING ROUTES (Public)
// ============================================================================

// Track email open (1x1 pixel)
app.get('/track/open/:trackingId', async (req, res) => {
  try {
    const { trackingId } = req.params;
    const userAgent = req.headers['user-agent'] || '';
    const ip = req.ip || req.connection.remoteAddress;
    
    await db.recordOpen(trackingId, userAgent, ip);
  } catch (error) {
    console.error('Track open error:', error);
  }
  
  // Return 1x1 transparent GIF
  const pixel = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
  res.set('Content-Type', 'image/gif');
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.send(pixel);
});

// Track link click
app.get('/track/click/:trackingId', async (req, res) => {
  try {
    const { trackingId } = req.params;
    const { url } = req.query;
    const userAgent = req.headers['user-agent'] || '';
    const ip = req.ip || req.connection.remoteAddress;
    
    await db.recordClick(trackingId, url, userAgent, ip);
    
    if (url) {
      return res.redirect(decodeURIComponent(url));
    }
  } catch (error) {
    console.error('Track click error:', error);
  }
  
  res.redirect(FRONTEND_URL);
});

// Unsubscribe page
app.get('/unsubscribe', async (req, res) => {
  const { email } = req.query;
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Unsubscribe</title>
      <style>
        body { font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
        .card { background: #f9fafb; border-radius: 12px; padding: 40px; }
        h1 { color: #111827; margin-bottom: 16px; }
        p { color: #6b7280; margin-bottom: 24px; }
        button { background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; padding: 12px 32px; border-radius: 8px; font-size: 16px; cursor: pointer; }
        button:hover { opacity: 0.9; }
        .success { color: #10b981; }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>Unsubscribe</h1>
        <p>Are you sure you want to unsubscribe <strong>${email}</strong> from our emails?</p>
        <form action="/unsubscribe" method="POST">
          <input type="hidden" name="email" value="${email}" />
          <button type="submit">Yes, Unsubscribe Me</button>
        </form>
      </div>
    </body>
    </html>
  `);
});

app.post('/unsubscribe', express.urlencoded({ extended: true }), async (req, res) => {
  const { email } = req.body;
  
  try {
    await db.unsubscribeContact(email, 'User requested', 'unsubscribe_page', req.ip);
    await db.updateDailyStats('emails_unsubscribed');
    
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Unsubscribed</title>
        <style>
          body { font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; text-align: center; }
          .card { background: #d1fae5; border-radius: 12px; padding: 40px; }
          h1 { color: #065f46; margin-bottom: 16px; }
          p { color: #047857; }
        </style>
      </head>
      <body>
        <div class="card">
          <h1>✓ Unsubscribed</h1>
          <p>You've been successfully unsubscribed and won't receive any more emails from us.</p>
        </div>
      </body>
      </html>
    `);
  } catch (error) {
    res.status(500).send('An error occurred');
  }
});

// ============================================================================
// AUTHENTICATION ROUTES
// ============================================================================

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const user = await db.findUserByEmail(email);
    if (!user || !user.active) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: { id: user.id, email: user.email, name: user.name, role: user.role }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword || newPassword.length < 8) {
      return res.status(400).json({ error: 'Valid passwords required' });
    }

    const user = await db.findUserByEmail(req.user.email);
    const valid = await bcrypt.compare(currentPassword, user.password);
    if (!valid) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    await db.updateUserPassword(req.user.id, newPassword);
    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ============================================================================
// USER MANAGEMENT ROUTES
// ============================================================================

app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  const users = await db.getAllUsers();
  res.json({ users });
});

app.post('/api/users/invite', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { email, role = 'user' } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    const existing = await db.findUserByEmail(email);
    if (existing) return res.status(400).json({ error: 'User already exists' });

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await db.createInvitation(token, email, role, expiresAt);

    res.json({
      message: 'Invitation created',
      inviteLink: `${FRONTEND_URL}/accept-invite/${token}`,
      expiresAt
    });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/users/invitations', authenticateToken, requireAdmin, async (req, res) => {
  const invitations = await db.getAllInvitations();
  res.json({ invitations });
});

app.post('/api/users/accept-invite', async (req, res) => {
  try {
    const { token, name, password } = req.body;
    if (!token || !name || !password || password.length < 8) {
      return res.status(400).json({ error: 'Valid token, name, and password required' });
    }

    const invitation = await db.findInvitationByToken(token);
    if (!invitation) return res.status(404).json({ error: 'Invalid or expired invitation' });

    const user = await db.createUser(invitation.email, password, name, invitation.role);
    await db.deleteInvitation(token);

    const authToken = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ token: authToken, user });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/users/:id/activate', authenticateToken, requireAdmin, async (req, res) => {
  await db.updateUserStatus(req.params.id, true);
  res.json({ message: 'User activated' });
});

app.post('/api/users/:id/deactivate', authenticateToken, requireAdmin, async (req, res) => {
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: 'Cannot deactivate yourself' });
  }
  await db.updateUserStatus(req.params.id, false);
  res.json({ message: 'User deactivated' });
});

app.delete('/api/users/invitations/:token', authenticateToken, requireAdmin, async (req, res) => {
  await db.deleteInvitation(req.params.token);
  res.json({ message: 'Invitation deleted' });
});

// ============================================================================
// WARMING ROUTES
// ============================================================================

app.get('/api/warming/accounts', authenticateToken, async (req, res) => {
  const accounts = await db.getAllWarmingAccounts();
  // Don't expose passwords
  const safeAccounts = accounts.map(a => ({ ...a, smtp_pass: '***' }));
  res.json({ accounts: safeAccounts });
});

app.post('/api/warming/accounts', authenticateToken, async (req, res) => {
  try {
    const account = await db.createWarmingAccount(req.body);
    res.json({ account: { ...account, smtp_pass: '***' } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/warming/accounts/:id', authenticateToken, async (req, res) => {
  await db.deleteWarmingAccount(req.params.id);
  res.json({ message: 'Account deleted' });
});

app.post('/api/smtp/test', authenticateToken, async (req, res) => {
  try {
    const { smtp_host, smtp_port, smtp_user, smtp_pass } = req.body;
    const transporter = nodemailer.createTransport({
      host: smtp_host,
      port: smtp_port,
      secure: smtp_port === 465,
      auth: { user: smtp_user, pass: smtp_pass }
    });
    await transporter.verify();
    res.json({ success: true, message: 'SMTP connection successful' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// CONTACT ROUTES
// ============================================================================

app.get('/api/contacts', authenticateToken, async (req, res) => {
  const contacts = await db.getAllContacts();
  res.json({ contacts });
});

app.post('/api/contacts', authenticateToken, async (req, res) => {
  try {
    if (Array.isArray(req.body)) {
      const contacts = await db.bulkCreateContacts(req.body);
      await db.updateDailyStats('new_contacts');
      res.json({ contacts, count: contacts.length });
    } else {
      const contact = await db.createContact(req.body);
      res.json({ contact });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/contacts/:id', authenticateToken, async (req, res) => {
  const contact = await db.getContactById(req.params.id);
  if (!contact) return res.status(404).json({ error: 'Contact not found' });
  res.json({ contact });
});

// ============================================================================
// TEMPLATE ROUTES
// ============================================================================

app.get('/api/templates', authenticateToken, async (req, res) => {
  const templates = await db.getAllTemplates();
  res.json({ templates });
});

app.post('/api/templates', authenticateToken, async (req, res) => {
  try {
    const template = await db.createTemplate(req.body, req.user.id);
    res.json({ template });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/templates/:id', authenticateToken, async (req, res) => {
  try {
    const template = await db.updateTemplate(req.params.id, req.body);
    res.json({ template });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/templates/:id', authenticateToken, async (req, res) => {
  await db.deleteTemplate(req.params.id);
  res.json({ message: 'Template deleted' });
});

// ============================================================================
// CAMPAIGN ROUTES
// ============================================================================

app.get('/api/campaigns', authenticateToken, async (req, res) => {
  const campaigns = await db.getAllCampaigns();
  res.json({ campaigns });
});

app.get('/api/campaigns/:id', authenticateToken, async (req, res) => {
  const campaign = await db.getCampaignAnalytics(req.params.id);
  if (!campaign) return res.status(404).json({ error: 'Campaign not found' });
  res.json({ campaign });
});

app.post('/api/campaigns', authenticateToken, async (req, res) => {
  try {
    const campaign = await db.createCampaign(req.body, req.user.id);
    res.json({ campaign });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/campaigns/:id/start', authenticateToken, async (req, res) => {
  try {
    const { contactIds } = req.body;
    const campaign = await db.getCampaignById(req.params.id);
    
    if (!campaign) return res.status(404).json({ error: 'Campaign not found' });
    
    // Add contacts to queue
    let added = 0;
    for (const contactId of (contactIds || [])) {
      const contact = await db.getContactById(contactId);
      if (contact && !contact.unsubscribed) {
        await db.addToEmailQueue({
          campaign_id: campaign.id,
          contact_id: contact.id,
          to_email: contact.email,
          to_name: `${contact.first_name || ''} ${contact.last_name || ''}`.trim(),
          from_email: campaign.from_email,
          from_name: campaign.from_name,
          subject: campaign.subject,
          body: campaign.body
        });
        added++;
      }
    }

    await db.updateCampaignStatus(req.params.id, 'sending');
    res.json({ message: `Campaign started with ${added} contacts` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/campaigns/:id/pause', authenticateToken, async (req, res) => {
  await db.updateCampaignStatus(req.params.id, 'paused');
  res.json({ message: 'Campaign paused' });
});

app.post('/api/campaigns/:id/resume', authenticateToken, async (req, res) => {
  await db.updateCampaignStatus(req.params.id, 'sending');
  res.json({ message: 'Campaign resumed' });
});

// ============================================================================
// SEQUENCE ROUTES
// ============================================================================

app.get('/api/sequences', authenticateToken, async (req, res) => {
  const sequences = await db.getAllSequences();
  res.json({ sequences });
});

app.get('/api/sequences/:id', authenticateToken, async (req, res) => {
  const sequence = await db.getSequenceWithSteps(req.params.id);
  if (!sequence) return res.status(404).json({ error: 'Sequence not found' });
  res.json({ sequence });
});

app.post('/api/sequences', authenticateToken, async (req, res) => {
  try {
    const { name, description, from_name, from_email, steps } = req.body;
    
    const sequence = await db.createSequence({
      name, description, from_name, from_email
    }, req.user.id);

    // Create steps
    if (steps && steps.length > 0) {
      for (let i = 0; i < steps.length; i++) {
        await db.createSequenceStep(sequence.id, {
          ...steps[i],
          step_number: i + 1
        });
      }
    }

    const fullSequence = await db.getSequenceWithSteps(sequence.id);
    res.json({ sequence: fullSequence });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/sequences/:id/add-contacts', authenticateToken, async (req, res) => {
  try {
    const { contactIds } = req.body;
    const added = await db.addContactsToSequence(req.params.id, contactIds);
    res.json({ message: `${added} contacts added to sequence` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/sequences/:id/start', authenticateToken, async (req, res) => {
  try {
    await db.query('UPDATE sequences SET status = $1 WHERE id = $2', ['active', req.params.id]);
    res.json({ message: 'Sequence started' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/sequences/:id/pause', authenticateToken, async (req, res) => {
  try {
    await db.query('UPDATE sequences SET status = $1 WHERE id = $2', ['paused', req.params.id]);
    res.json({ message: 'Sequence paused' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// ANALYTICS ROUTES
// ============================================================================

app.get('/api/analytics/overview', authenticateToken, async (req, res) => {
  try {
    const stats = await db.getOverallStats();
    res.json({ stats });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/analytics/daily', authenticateToken, async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const stats = await db.getDailyStats(parseInt(days));
    res.json({ stats });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/analytics/campaigns/:id', authenticateToken, async (req, res) => {
  try {
    const analytics = await db.getCampaignAnalytics(req.params.id);
    if (!analytics) return res.status(404).json({ error: 'Campaign not found' });
    res.json({ analytics });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// ERROR HANDLING
// ============================================================================

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

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
║  🚀 Cold Email System v2.0 - All Features Enabled              ║
║                                                                ║
║  Port: ${PORT}                                                    ║
║  Database: ${process.env.DATABASE_URL ? '✅ Connected' : '❌ Not configured'}                               ║
║                                                                ║
║  Features:                                                     ║
║  ✅ Authentication & User Management                           ║
║  ✅ Email Templates                                             ║
║  ✅ Campaigns with Tracking                                     ║
║  ✅ Follow-up Sequences                                         ║
║  ✅ Open & Click Tracking                                       ║
║  ✅ Unsubscribe Management                                      ║
║  ✅ Analytics Dashboard                                         ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
  `);
  
  // Start background email processor
  startEmailProcessor();
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Shutting down...');
  clearInterval(emailJobInterval);
  process.exit(0);
});
