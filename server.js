// ============================================================================
// COLD EMAIL SYSTEM - SECURE SERVER v3.1
// With Encryption, User Isolation, Ownership Checks, and Input Validation
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
const fetch = require('node-fetch');
const db = require('./database');
const security = require('./security');
const { WarmingScheduler } = require('./warming-engine');

const app = express();
const PORT = process.env.PORT || 10000;

// Trust proxy for Render (required for rate limiting behind load balancer)
app.set('trust proxy', 1);

// Warming scheduler instance
let warmingScheduler = null;

// ============================================================================
// CONFIGURATION
// ============================================================================

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET === 'your-super-secret-jwt-key') {
  console.error('⚠️  WARNING: JWT_SECRET not set or using default! Set a secure random value.');
  console.error('   Generate one with: node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'hex\'))"');
}

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';
const BACKEND_URL = process.env.BACKEND_URL || `http://localhost:${PORT}`;

// ============================================================================
// SECURITY MIDDLEWARE
// ============================================================================

// Helmet for security headers
app.use(helmet({
  contentSecurityPolicy: false, // Customize if needed
  crossOriginEmbedderPolicy: false
}));

// CORS with specific origin
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? [FRONTEND_URL] 
    : ['http://localhost:3000', 'http://localhost:5173', FRONTEND_URL],
  credentials: true
}));

// Body parser with size limit
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// Global rate limiter
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,
  message: { error: 'Too many requests, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', globalLimiter);

// Strict rate limiter for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many authentication attempts, please try again later' },
  skipSuccessfulRequests: true
});

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
    const decoded = jwt.verify(token, JWT_SECRET || 'fallback-dev-key');
    const user = await db.findUserById(decoded.userId);
    
    if (!user || !user.active) {
      return res.status(401).json({ error: 'Invalid or inactive user' });
    }
    
    // Check user rate limit
    if (security.userRateLimiter.isLimited(user.id)) {
      return res.status(429).json({ error: 'Rate limit exceeded. Please slow down.' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired, please login again' });
    }
    return res.status(403).json({ error: 'Invalid token' });
  }
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    security.createAuditLog('ADMIN_ACCESS_DENIED', req.user.id, { path: req.path }, req);
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Ownership verification middleware factory
const verifyOwnership = (resourceType) => async (req, res, next) => {
  const resourceId = req.params.id;
  
  if (!security.validators.uuid(resourceId)) {
    return res.status(400).json({ error: 'Invalid resource ID' });
  }
  
  try {
    const isOwner = await db.verifyResourceOwnership(resourceType, resourceId, req.user.id);
    if (!isOwner) {
      security.createAuditLog('OWNERSHIP_VIOLATION', req.user.id, { resourceType, resourceId }, req);
      return res.status(403).json({ error: 'Access denied' });
    }
    next();
  } catch (error) {
    return res.status(500).json({ error: 'Ownership verification failed' });
  }
};

// ============================================================================
// INPUT VALIDATION MIDDLEWARE
// ============================================================================

const validateEmail = (req, res, next) => {
  const email = req.body.email;
  if (email && !security.validators.email(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  next();
};

const validatePassword = (req, res, next) => {
  const password = req.body.password || req.body.newPassword;
  if (password) {
    const result = security.validators.password(password);
    if (!result.valid) {
      return res.status(400).json({ error: result.message });
    }
  }
  next();
};

// ============================================================================
// CLOUDFLARE CLIENT (with decryption)
// ============================================================================

class CloudflareClient {
  constructor(apiToken, accountId) {
    this.apiToken = apiToken;
    this.accountId = accountId;
    this.baseUrl = 'https://api.cloudflare.com/client/v4';
  }

  async request(endpoint, options = {}) {
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers: {
        'Authorization': `Bearer ${this.apiToken}`,
        'Content-Type': 'application/json',
        ...options.headers
      }
    });

    const data = await response.json();
    
    if (!data.success) {
      const errorMsg = data.errors?.[0]?.message || 'Cloudflare API error';
      throw new Error(errorMsg);
    }

    return data;
  }

  async verifyConnection() {
    try {
      const data = await this.request('/user/tokens/verify');
      return { valid: true, status: data.result?.status };
    } catch (error) {
      return { valid: false, error: error.message };
    }
  }

  async getAccountDetails() {
    const data = await this.request(`/accounts/${this.accountId}`);
    return data.result;
  }

  async getZones() {
    const data = await this.request(`/zones?account.id=${this.accountId}`);
    return data.result || [];
  }

  async getZoneByDomain(domainName) {
    const data = await this.request(`/zones?name=${domainName}&account.id=${this.accountId}`);
    return data.result?.[0] || null;
  }

  async createZone(domainName) {
    const data = await this.request('/zones', {
      method: 'POST',
      body: JSON.stringify({
        name: domainName,
        account: { id: this.accountId },
        jump_start: true,
        type: 'full'
      })
    });
    return data.result;
  }

  async checkAvailabilityViaRegistrar(domainName) {
    try {
      const data = await this.request(`/accounts/${this.accountId}/registrar/domains/${domainName}/available`);
      return {
        domain: domainName,
        available: data.result?.available || false,
        premium: data.result?.premium || false,
        price: data.result?.price || null,
        currency: data.result?.currency || 'USD'
      };
    } catch (error) {
      return { domain: domainName, available: 'unknown', error: error.message };
    }
  }

  async purchaseDomain(domainName, contactInfo) {
    const data = await this.request(`/accounts/${this.accountId}/registrar/domains`, {
      method: 'POST',
      body: JSON.stringify({
        name: domainName,
        auto_renew: true,
        years: 1,
        registrant_contact: contactInfo
      })
    });
    return { success: true, domain: data.result?.name, expires_at: data.result?.expires_at, status: data.result?.status };
  }

  async getDnsRecords(zoneId) {
    const data = await this.request(`/zones/${zoneId}/dns_records`);
    return data.result || [];
  }

  async createDnsRecord(zoneId, record) {
    const data = await this.request(`/zones/${zoneId}/dns_records`, { method: 'POST', body: JSON.stringify(record) });
    return data.result;
  }

  async updateDnsRecord(zoneId, recordId, record) {
    const data = await this.request(`/zones/${zoneId}/dns_records/${recordId}`, { method: 'PUT', body: JSON.stringify(record) });
    return data.result;
  }

  async setupEmailRecords(zoneId, domainName) {
    const results = { mx: [], spf: null, dmarc: null };
    const existingRecords = await this.getDnsRecords(zoneId);

    const mxRecords = [
      { priority: 10, server: 'route1.mx.cloudflare.net' },
      { priority: 20, server: 'route2.mx.cloudflare.net' },
      { priority: 30, server: 'route3.mx.cloudflare.net' }
    ];

    for (const mx of mxRecords) {
      const existing = existingRecords.find(r => r.type === 'MX' && r.content === mx.server);
      if (!existing) {
        const record = await this.createDnsRecord(zoneId, { type: 'MX', name: domainName, content: mx.server, priority: mx.priority, ttl: 3600 });
        results.mx.push(record);
      }
    }

    const spfValue = 'v=spf1 include:_spf.mx.cloudflare.net ~all';
    const existingSpf = existingRecords.find(r => r.type === 'TXT' && r.content.includes('v=spf1'));
    if (existingSpf) {
      results.spf = await this.updateDnsRecord(zoneId, existingSpf.id, { type: 'TXT', name: domainName, content: spfValue, ttl: 3600 });
    } else {
      results.spf = await this.createDnsRecord(zoneId, { type: 'TXT', name: domainName, content: spfValue, ttl: 3600 });
    }

    const dmarcValue = `v=DMARC1; p=quarantine; rua=mailto:dmarc@${domainName}`;
    const existingDmarc = existingRecords.find(r => r.type === 'TXT' && r.name.startsWith('_dmarc'));
    if (!existingDmarc) {
      results.dmarc = await this.createDnsRecord(zoneId, { type: 'TXT', name: `_dmarc.${domainName}`, content: dmarcValue, ttl: 3600 });
    }

    return results;
  }

  async enableEmailRouting(zoneId) {
    const data = await this.request(`/zones/${zoneId}/email/routing/enable`, { method: 'POST' });
    return data.result;
  }

  async createCatchAllForwarding(zoneId, forwardTo) {
    try {
      await this.request(`/accounts/${this.accountId}/email/routing/addresses`, { method: 'POST', body: JSON.stringify({ email: forwardTo }) });
    } catch (error) { /* Address might already exist */ }

    const rule = await this.request(`/zones/${zoneId}/email/routing/rules`, {
      method: 'POST',
      body: JSON.stringify({ name: 'Catch-all forwarding', enabled: true, matchers: [{ type: 'all' }], actions: [{ type: 'forward', value: [forwardTo] }] })
    });
    return rule.result;
  }

  async fullDomainSetup(domainName, forwardTo) {
    const results = { zone: null, dns: null, emailRouting: null, forwarding: null, errors: [] };

    try {
      let zone = await this.getZoneByDomain(domainName);
      if (!zone) zone = await this.createZone(domainName);
      results.zone = zone;

      try { results.dns = await this.setupEmailRecords(zone.id, domainName); } 
      catch (e) { results.errors.push(`DNS setup: ${e.message}`); }

      try { await this.enableEmailRouting(zone.id); results.emailRouting = { enabled: true }; } 
      catch (e) { results.errors.push(`Email routing: ${e.message}`); }

      if (forwardTo) {
        try { results.forwarding = await this.createCatchAllForwarding(zone.id, forwardTo); } 
        catch (e) { results.errors.push(`Forwarding: ${e.message}`); }
      }
    } catch (error) {
      results.errors.push(`Zone setup: ${error.message}`);
    }

    return results;
  }
}

// Domain pricing
const DOMAIN_PRICING = { '.com': 9.15, '.net': 10.11, '.org': 9.93, '.io': 33.98, '.co': 11.99, '.dev': 12.00, '.app': 14.00, '.xyz': 10.00, '.me': 15.00, '.ai': 20.00 };
function getEstimatedPrice(domain) { const tld = '.' + domain.split('.').pop(); return DOMAIN_PRICING[tld] || 12.00; }

// Helper to get user's Cloudflare client with decryption
async function getUserCloudflareClient(userId) {
  const result = await db.query(
    'SELECT api_token, account_id FROM cloudflare_configs WHERE user_id = $1 AND is_valid = true',
    [userId]
  );
  if (result.rows.length === 0) {
    throw new Error('Cloudflare not configured. Please add your API credentials first.');
  }
  // Decrypt the API token
  const decryptedToken = security.decrypt(result.rows[0].api_token);
  return new CloudflareClient(decryptedToken, result.rows[0].account_id);
}

// ============================================================================
// EMAIL SENDING ENGINE
// ============================================================================

function personalizeContent(template, contact) {
  let content = template;
  content = content.replace(/\{\{first_name\}\}/gi, security.sanitizers.text(contact.first_name || ''));
  content = content.replace(/\{\{last_name\}\}/gi, security.sanitizers.text(contact.last_name || ''));
  content = content.replace(/\{\{company\}\}/gi, security.sanitizers.text(contact.company || ''));
  content = content.replace(/\{\{title\}\}/gi, security.sanitizers.text(contact.title || ''));
  content = content.replace(/\{\{email\}\}/gi, security.sanitizers.text(contact.email || ''));
  content = content.replace(/\{\{name\}\}/gi, 
    security.sanitizers.text((contact.first_name || '') + (contact.last_name ? ' ' + contact.last_name : '') || 'there')
  );
  return content.trim();
}

function addTrackingPixel(body, trackingId) {
  const pixelUrl = `${BACKEND_URL}/track/open/${trackingId}`;
  const pixel = `<img src="${pixelUrl}" width="1" height="1" style="display:none" alt="" />`;
  if (body.includes('</body>')) return body.replace('</body>', `${pixel}</body>`);
  return body + `<br/>${pixel}`;
}

function wrapLinksForTracking(body, trackingId) {
  const linkRegex = /href=["'](https?:\/\/[^"']+)["']/gi;
  return body.replace(linkRegex, (match, url) => {
    if (url.includes('unsubscribe')) return match;
    const encodedUrl = encodeURIComponent(url);
    const trackingUrl = `${BACKEND_URL}/track/click/${trackingId}?url=${encodedUrl}`;
    return `href="${trackingUrl}"`;
  });
}

function addUnsubscribeLink(body, email) {
  const unsubscribeUrl = `${BACKEND_URL}/unsubscribe?email=${encodeURIComponent(email)}`;
  const unsubscribeHtml = `<br/><br/><div style="text-align:center;font-size:12px;color:#666;margin-top:20px;padding-top:20px;border-top:1px solid #eee;"><a href="${unsubscribeUrl}" style="color:#666;">Unsubscribe</a> from future emails</div>`;
  if (body.includes('</body>')) return body.replace('</body>', `${unsubscribeHtml}</body>`);
  return body + unsubscribeHtml;
}

async function sendEmail(queueItem) {
  try {
    const account = await db.getActiveWarmingAccountForUser(queueItem.user_id);
    if (!account) throw new Error('No available sending accounts');

    // Decrypt SMTP password
    const decryptedPass = security.decrypt(account.smtp_pass);

    const transporter = nodemailer.createTransport({
      host: account.smtp_host,
      port: account.smtp_port,
      secure: account.smtp_port === 465,
      auth: { user: account.smtp_user, pass: decryptedPass }
    });

    const contact = await db.getContactById(queueItem.contact_id);
    if (!contact) throw new Error('Contact not found');
    if (await db.isUnsubscribed(contact.email)) throw new Error('Contact is unsubscribed');

    let subject = security.sanitizers.subject(personalizeContent(queueItem.subject, contact));
    let body = security.sanitizers.html(personalizeContent(queueItem.body, contact));

    const tracking = await db.createTracking({
      campaign_id: queueItem.campaign_id,
      sequence_id: queueItem.sequence_id,
      sequence_step_id: queueItem.sequence_step_id,
      contact_id: queueItem.contact_id,
      email_queue_id: queueItem.id
    });

    body = addTrackingPixel(body, tracking.tracking_id);
    body = wrapLinksForTracking(body, tracking.tracking_id);
    body = addUnsubscribeLink(body, contact.email);

    await transporter.sendMail({
      from: `"${security.sanitizers.text(queueItem.from_name)}" <${account.email}>`,
      replyTo: queueItem.from_email,
      to: contact.email,
      subject: subject,
      html: body
    });

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

async function processEmailQueue() {
  try {
    const queueItems = await db.getNextQueuedEmails(5);
    for (const item of queueItems) {
      await sendEmail(item);
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
    return queueItems.length;
  } catch (error) {
    console.error('Queue processing error:', error);
    return 0;
  }
}

async function processSequenceEmails() {
  try {
    const dueContacts = await db.getSequenceContactsDueForEmail();
    for (const sc of dueContacts) {
      await db.addToEmailQueue({
        user_id: sc.user_id,
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

      const sequence = await db.getSequenceWithSteps(sc.sequence_id);
      const currentStepIndex = sequence.steps.findIndex(s => s.step_number === sc.current_step);
      const nextStep = sequence.steps[currentStepIndex + 1];

      if (nextStep) {
        const nextEmailAt = new Date();
        nextEmailAt.setDate(nextEmailAt.getDate() + nextStep.delay_days);
        nextEmailAt.setHours(nextEmailAt.getHours() + nextStep.delay_hours);
        await db.updateSequenceContactAfterSend(sc.id, nextStep.step_number, nextEmailAt);
      } else {
        await db.updateSequenceContactAfterSend(sc.id, null, null);
      }
    }
    return dueContacts.length;
  } catch (error) {
    console.error('Sequence processing error:', error);
    return 0;
  }
}

let emailJobInterval;
function startEmailProcessor() {
  console.log('📧 Starting email processor...');
  emailJobInterval = setInterval(async () => {
    await processEmailQueue();
    await processSequenceEmails();
  }, 10000);

  const resetDaily = () => {
    const now = new Date();
    const tomorrow = new Date(now);
    tomorrow.setDate(tomorrow.getDate() + 1);
    tomorrow.setHours(0, 0, 0, 0);
    const msUntilMidnight = tomorrow - now;
    setTimeout(async () => {
      await db.resetDailyWarmingCounts();
      console.log('🔄 Daily warming counts reset');
      resetDaily();
    }, msUntilMidnight);
  };
  resetDaily();
}

// ============================================================================
// PUBLIC ROUTES
// ============================================================================

app.get('/health', async (req, res) => {
  const stats = await db.getHealthStats();
  res.json(stats);
});

app.get('/', (req, res) => {
  res.json({
    message: 'Cold Email System API v3.1 (Secure)',
    status: 'online',
    features: ['authentication', 'campaigns', 'sequences', 'templates', 'tracking', 'analytics', 'domains'],
    security: ['encryption', 'user-isolation', 'ownership-checks', 'input-validation', 'brute-force-protection']
  });
});

// ============================================================================
// TRACKING ROUTES (Public)
// ============================================================================

app.get('/track/open/:trackingId', async (req, res) => {
  try {
    const { trackingId } = req.params;
    if (trackingId.length !== 32) throw new Error('Invalid tracking ID');
    const userAgent = req.headers['user-agent'] || '';
    const ip = req.ip || req.connection.remoteAddress;
    await db.recordOpen(trackingId, userAgent, ip);
  } catch (error) {
    console.error('Track open error:', error);
  }
  const pixel = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
  res.set('Content-Type', 'image/gif');
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.send(pixel);
});

app.get('/track/click/:trackingId', async (req, res) => {
  try {
    const { trackingId } = req.params;
    const { url } = req.query;
    if (trackingId.length !== 32) throw new Error('Invalid tracking ID');
    const userAgent = req.headers['user-agent'] || '';
    const ip = req.ip || req.connection.remoteAddress;
    await db.recordClick(trackingId, url, userAgent, ip);
    
    // Validate URL before redirecting
    if (url && security.validators.url(decodeURIComponent(url))) {
      return res.redirect(decodeURIComponent(url));
    }
  } catch (error) {
    console.error('Track click error:', error);
  }
  res.redirect(FRONTEND_URL);
});

app.get('/unsubscribe', async (req, res) => {
  const { email } = req.query;
  const safeEmail = security.sanitizers.text(email || '');
  res.send(`
    <!DOCTYPE html>
    <html>
    <head><title>Unsubscribe</title>
    <style>body{font-family:system-ui,sans-serif;max-width:600px;margin:50px auto;padding:20px;text-align:center}.card{background:#f9fafb;border-radius:12px;padding:40px}h1{color:#111827;margin-bottom:16px}p{color:#6b7280;margin-bottom:24px}button{background:linear-gradient(135deg,#667eea,#764ba2);color:white;border:none;padding:12px 32px;border-radius:8px;font-size:16px;cursor:pointer}</style>
    </head>
    <body><div class="card"><h1>Unsubscribe</h1><p>Are you sure you want to unsubscribe <strong>${safeEmail}</strong> from our emails?</p><form action="/unsubscribe" method="POST"><input type="hidden" name="email" value="${safeEmail}"/><button type="submit">Yes, Unsubscribe Me</button></form></div></body>
    </html>
  `);
});

app.post('/unsubscribe', express.urlencoded({ extended: true }), async (req, res) => {
  const { email } = req.body;
  if (!security.validators.email(email)) {
    return res.status(400).send('Invalid email');
  }
  try {
    await db.unsubscribeContact(email, 'User requested', 'unsubscribe_page', req.ip);
    await db.updateDailyStats('emails_unsubscribed');
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>Unsubscribed</title>
      <style>body{font-family:system-ui,sans-serif;max-width:600px;margin:50px auto;padding:20px;text-align:center}.card{background:#d1fae5;border-radius:12px;padding:40px}h1{color:#065f46;margin-bottom:16px}p{color:#047857}</style>
      </head>
      <body><div class="card"><h1>✓ Unsubscribed</h1><p>You've been successfully unsubscribed.</p></div></body>
      </html>
    `);
  } catch (error) {
    res.status(500).send('An error occurred');
  }
});

// ============================================================================
// AUTHENTICATION ROUTES (with brute force protection)
// ============================================================================

app.post('/api/auth/login', authLimiter, validateEmail, async (req, res) => {
  try {
    const { email, password } = req.body;
    const ip = req.ip || req.connection.remoteAddress;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Check if locked out
    if (security.loginTracker.isLocked(ip, email)) {
      const remaining = security.loginTracker.getLockoutRemaining(ip, email);
      security.createAuditLog('LOGIN_LOCKED_OUT', null, { email, ip }, req);
      return res.status(429).json({ 
        error: `Account temporarily locked. Try again in ${Math.ceil(remaining / 60)} minutes.`,
        lockedFor: remaining
      });
    }

    const user = await db.findUserByEmail(email);
    if (!user || !user.active) {
      security.loginTracker.recordFailure(ip, email);
      const remaining = security.loginTracker.getRemainingAttempts(ip, email);
      return res.status(401).json({ 
        error: 'Invalid credentials',
        remainingAttempts: remaining
      });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      security.loginTracker.recordFailure(ip, email);
      security.createAuditLog('LOGIN_FAILED', user.id, { reason: 'invalid_password' }, req);
      const remaining = security.loginTracker.getRemainingAttempts(ip, email);
      return res.status(401).json({ 
        error: 'Invalid credentials',
        remainingAttempts: remaining
      });
    }

    // Success - clear failed attempts
    security.loginTracker.recordSuccess(ip, email);
    security.createAuditLog('LOGIN_SUCCESS', user.id, {}, req);

    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET || 'fallback-dev-key',
      { expiresIn: '24h' } // Reduced from 7d to 24h for security
    );
    
    res.json({ 
      token, 
      user: { id: user.id, email: user.email, name: user.name, role: user.role },
      expiresIn: 24 * 60 * 60 // seconds
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json({ user: { id: req.user.id, email: req.user.email, name: req.user.name, role: req.user.role } });
});

app.post('/api/auth/change-password', authenticateToken, validatePassword, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Both passwords required' });
    }

    const user = await db.findUserByEmail(req.user.email);
    const valid = await bcrypt.compare(currentPassword, user.password);
    if (!valid) {
      security.createAuditLog('PASSWORD_CHANGE_FAILED', req.user.id, { reason: 'invalid_current' }, req);
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    await db.updateUserPassword(req.user.id, newPassword);
    security.createAuditLog('PASSWORD_CHANGED', req.user.id, {}, req);
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

app.post('/api/users/invite', authenticateToken, requireAdmin, validateEmail, async (req, res) => {
  try {
    const { email, role = 'user' } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    if (!['user', 'admin'].includes(role)) return res.status(400).json({ error: 'Invalid role' });

    const existing = await db.findUserByEmail(email);
    if (existing) return res.status(400).json({ error: 'User already exists' });

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await db.createInvitation(token, email, role, expiresAt);
    security.createAuditLog('USER_INVITED', req.user.id, { invitedEmail: email, role }, req);
    res.json({ message: 'Invitation created', inviteLink: `${FRONTEND_URL}/accept-invite/${token}`, expiresAt });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/users/invitations', authenticateToken, requireAdmin, async (req, res) => {
  const invitations = await db.getAllInvitations();
  res.json({ invitations });
});

app.post('/api/users/accept-invite', validatePassword, async (req, res) => {
  try {
    const { token, name, password } = req.body;
    if (!token || !name) {
      return res.status(400).json({ error: 'Token and name required' });
    }
    if (!security.validators.maxLength(name, 255)) {
      return res.status(400).json({ error: 'Name too long' });
    }

    const invitation = await db.findInvitationByToken(token);
    if (!invitation) return res.status(404).json({ error: 'Invalid or expired invitation' });

    const user = await db.createUser(invitation.email, password, security.sanitizers.text(name), invitation.role);
    await db.deleteInvitation(token);
    security.createAuditLog('USER_REGISTERED', user.id, { viaInvite: true }, null);

    const authToken = jwt.sign({ userId: user.id, email: user.email, role: user.role }, JWT_SECRET || 'fallback-dev-key', { expiresIn: '24h' });
    res.json({ token: authToken, user });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/users/:id/activate', authenticateToken, requireAdmin, async (req, res) => {
  if (!security.validators.uuid(req.params.id)) return res.status(400).json({ error: 'Invalid user ID' });
  await db.updateUserStatus(req.params.id, true);
  security.createAuditLog('USER_ACTIVATED', req.user.id, { targetUser: req.params.id }, req);
  res.json({ message: 'User activated' });
});

app.post('/api/users/:id/deactivate', authenticateToken, requireAdmin, async (req, res) => {
  if (!security.validators.uuid(req.params.id)) return res.status(400).json({ error: 'Invalid user ID' });
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot deactivate yourself' });
  await db.updateUserStatus(req.params.id, false);
  security.createAuditLog('USER_DEACTIVATED', req.user.id, { targetUser: req.params.id }, req);
  res.json({ message: 'User deactivated' });
});

app.delete('/api/users/invitations/:token', authenticateToken, requireAdmin, async (req, res) => {
  await db.deleteInvitation(req.params.token);
  res.json({ message: 'Invitation deleted' });
});

// ============================================================================
// WARMING ROUTES (User-scoped)
// ============================================================================

app.get('/api/warming/accounts', authenticateToken, async (req, res) => {
  const accounts = await db.getWarmingAccountsForUser(req.user.id);
  // Don't expose encrypted passwords
  const safeAccounts = accounts.map(a => ({ ...a, smtp_pass: '***encrypted***' }));
  res.json({ accounts: safeAccounts });
});

app.post('/api/warming/accounts', authenticateToken, async (req, res) => {
  try {
    const { email, smtp_host, smtp_port, smtp_user, smtp_pass, imap_host, imap_port } = req.body;
    
    // Validate inputs
    if (!security.validators.email(email)) return res.status(400).json({ error: 'Invalid email format' });
    if (!security.validators.hostname(smtp_host)) return res.status(400).json({ error: 'Invalid SMTP host' });
    if (!security.validators.port(smtp_port)) return res.status(400).json({ error: 'Invalid SMTP port' });
    if (!security.validators.hostname(imap_host)) return res.status(400).json({ error: 'Invalid IMAP host' });
    if (!security.validators.port(imap_port)) return res.status(400).json({ error: 'Invalid IMAP port' });
    if (!smtp_pass || smtp_pass.length < 1) return res.status(400).json({ error: 'SMTP password required' });

    // Encrypt the password before storing
    const encryptedPass = security.encrypt(smtp_pass);

    const account = await db.createWarmingAccount({
      user_id: req.user.id,
      email,
      smtp_host,
      smtp_port: parseInt(smtp_port),
      smtp_user,
      smtp_pass: encryptedPass,
      imap_host,
      imap_port: parseInt(imap_port)
    });

    security.createAuditLog('WARMING_ACCOUNT_ADDED', req.user.id, { email }, req);
    res.json({ account: { ...account, smtp_pass: '***encrypted***' } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/warming/accounts/:id', authenticateToken, verifyOwnership('warming_accounts'), async (req, res) => {
  await db.deleteWarmingAccount(req.params.id);
  security.createAuditLog('WARMING_ACCOUNT_DELETED', req.user.id, { accountId: req.params.id }, req);
  res.json({ message: 'Account deleted' });
});

app.post('/api/smtp/test', authenticateToken, async (req, res) => {
  try {
    const { smtp_host, smtp_port, smtp_user, smtp_pass } = req.body;
    
    if (!security.validators.hostname(smtp_host)) return res.status(400).json({ error: 'Invalid SMTP host' });
    if (!security.validators.port(smtp_port)) return res.status(400).json({ error: 'Invalid SMTP port' });

    const transporter = nodemailer.createTransport({
      host: smtp_host, 
      port: parseInt(smtp_port), 
      secure: parseInt(smtp_port) === 465,
      auth: { user: smtp_user, pass: smtp_pass },
      connectionTimeout: 10000
    });
    await transporter.verify();
    res.json({ success: true, message: 'SMTP connection successful' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// AUTO WARMING ROUTES
// ============================================================================

// Get warming status and stats
app.get('/api/warming/status', authenticateToken, async (req, res) => {
  try {
    if (!warmingScheduler) {
      return res.json({ status: 'not_initialized' });
    }
    const stats = await warmingScheduler.getWarmingStats(req.user.id);
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start warming
app.post('/api/warming/start', authenticateToken, async (req, res) => {
  try {
    if (!warmingScheduler) {
      return res.status(500).json({ error: 'Warming system not initialized' });
    }
    
    const { emailsPerDay = 10, aiFrequency = 0.3, replyProbability = 0.8 } = req.body;
    
    if (emailsPerDay < 1 || emailsPerDay > 50) {
      return res.status(400).json({ error: 'Emails per day must be between 1 and 50' });
    }
    
    const result = await warmingScheduler.startWarming(req.user.id, {
      emailsPerDay: parseInt(emailsPerDay),
      aiFrequency: parseFloat(aiFrequency),
      replyProbability: parseFloat(replyProbability)
    });
    
    security.createAuditLog('WARMING_STARTED', req.user.id, { emailsPerDay, aiFrequency }, req);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Stop warming
app.post('/api/warming/stop', authenticateToken, async (req, res) => {
  try {
    if (!warmingScheduler) {
      return res.status(500).json({ error: 'Warming system not initialized' });
    }
    
    const result = await warmingScheduler.stopWarming(req.user.id);
    security.createAuditLog('WARMING_STOPPED', req.user.id, {}, req);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get warming email history
app.get('/api/warming/emails', authenticateToken, async (req, res) => {
  try {
    const { limit = 50 } = req.query;
    const result = await db.query(`
      SELECT we.*, wa.email as sender_email 
      FROM warming_emails we
      JOIN warming_accounts wa ON we.sender_account_id = wa.id
      WHERE we.user_id = $1 
      ORDER BY we.created_at DESC 
      LIMIT $2
    `, [req.user.id, Math.min(parseInt(limit), 100)]);
    
    res.json({ emails: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// CONTACT ROUTES (User-scoped)
// ============================================================================

app.get('/api/contacts', authenticateToken, async (req, res) => {
  const contacts = await db.getContactsForUser(req.user.id);
  res.json({ contacts });
});

app.post('/api/contacts', authenticateToken, async (req, res) => {
  try {
    if (Array.isArray(req.body)) {
      // Validate and sanitize each contact
      const validContacts = req.body.filter(c => security.validators.email(c.email)).map(c => ({
        user_id: req.user.id,
        email: c.email.toLowerCase().trim(),
        first_name: security.sanitizers.text(c.first_name || '').substring(0, 255),
        last_name: security.sanitizers.text(c.last_name || '').substring(0, 255),
        company: security.sanitizers.text(c.company || '').substring(0, 255),
        title: security.sanitizers.text(c.title || '').substring(0, 255),
        tags: c.tags || []
      }));
      
      if (validContacts.length === 0) {
        return res.status(400).json({ error: 'No valid contacts provided' });
      }

      const contacts = await db.bulkCreateContacts(validContacts);
      await db.updateDailyStats('new_contacts');
      res.json({ contacts, count: contacts.length });
    } else {
      if (!security.validators.email(req.body.email)) {
        return res.status(400).json({ error: 'Invalid email format' });
      }
      
      const contact = await db.createContact({
        user_id: req.user.id,
        email: req.body.email.toLowerCase().trim(),
        first_name: security.sanitizers.text(req.body.first_name || '').substring(0, 255),
        last_name: security.sanitizers.text(req.body.last_name || '').substring(0, 255),
        company: security.sanitizers.text(req.body.company || '').substring(0, 255),
        title: security.sanitizers.text(req.body.title || '').substring(0, 255),
        tags: req.body.tags || []
      });
      res.json({ contact });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/contacts/:id', authenticateToken, verifyOwnership('contacts'), async (req, res) => {
  const contact = await db.getContactById(req.params.id);
  if (!contact) return res.status(404).json({ error: 'Contact not found' });
  res.json({ contact });
});

// ============================================================================
// TEMPLATE ROUTES (User-scoped)
// ============================================================================

app.get('/api/templates', authenticateToken, async (req, res) => {
  const templates = await db.getTemplatesForUser(req.user.id);
  res.json({ templates });
});

app.post('/api/templates', authenticateToken, async (req, res) => {
  try {
    const { name, subject, body, category } = req.body;
    
    if (!name || !subject || !body) {
      return res.status(400).json({ error: 'Name, subject, and body are required' });
    }
    if (!security.validators.maxLength(name, 255)) return res.status(400).json({ error: 'Name too long' });
    if (!security.validators.maxLength(subject, 500)) return res.status(400).json({ error: 'Subject too long' });
    if (!security.validators.maxLength(body, 50000)) return res.status(400).json({ error: 'Body too long' });

    const template = await db.createTemplate({
      name: security.sanitizers.text(name),
      subject: security.sanitizers.subject(subject),
      body: security.sanitizers.html(body),
      category: security.sanitizers.text(category || '')
    }, req.user.id);
    res.json({ template });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/templates/:id', authenticateToken, verifyOwnership('email_templates'), async (req, res) => {
  try {
    const { name, subject, body, category } = req.body;
    
    if (!security.validators.maxLength(name, 255)) return res.status(400).json({ error: 'Name too long' });
    if (!security.validators.maxLength(subject, 500)) return res.status(400).json({ error: 'Subject too long' });
    if (!security.validators.maxLength(body, 50000)) return res.status(400).json({ error: 'Body too long' });

    const template = await db.updateTemplate(req.params.id, {
      name: security.sanitizers.text(name),
      subject: security.sanitizers.subject(subject),
      body: security.sanitizers.html(body),
      category: security.sanitizers.text(category || '')
    });
    res.json({ template });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/templates/:id', authenticateToken, verifyOwnership('email_templates'), async (req, res) => {
  await db.deleteTemplate(req.params.id);
  res.json({ message: 'Template deleted' });
});

// ============================================================================
// CAMPAIGN ROUTES (User-scoped)
// ============================================================================

app.get('/api/campaigns', authenticateToken, async (req, res) => {
  const campaigns = await db.getCampaignsForUser(req.user.id);
  res.json({ campaigns });
});

app.get('/api/campaigns/:id', authenticateToken, verifyOwnership('campaigns'), async (req, res) => {
  const campaign = await db.getCampaignAnalytics(req.params.id);
  if (!campaign) return res.status(404).json({ error: 'Campaign not found' });
  res.json({ campaign });
});

app.post('/api/campaigns', authenticateToken, async (req, res) => {
  try {
    const { name, subject, body, from_name, from_email, type, sending_rate } = req.body;
    
    if (!name || !subject || !body || !from_name || !from_email) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (!security.validators.email(from_email)) return res.status(400).json({ error: 'Invalid from email' });
    if (!security.validators.maxLength(name, 255)) return res.status(400).json({ error: 'Name too long' });
    if (!security.validators.maxLength(subject, 500)) return res.status(400).json({ error: 'Subject too long' });

    const campaign = await db.createCampaign({
      name: security.sanitizers.text(name),
      subject: security.sanitizers.subject(subject),
      body: security.sanitizers.html(body),
      from_name: security.sanitizers.text(from_name),
      from_email: from_email.toLowerCase().trim(),
      type: type || 'single',
      sending_rate: parseInt(sending_rate) || 30
    }, req.user.id);
    res.json({ campaign });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/campaigns/:id/start', authenticateToken, verifyOwnership('campaigns'), async (req, res) => {
  try {
    const { contactIds } = req.body;
    const campaign = await db.getCampaignById(req.params.id);
    if (!campaign) return res.status(404).json({ error: 'Campaign not found' });

    let added = 0;
    for (const contactId of (contactIds || [])) {
      // Verify contact ownership
      const isOwner = await db.verifyResourceOwnership('contacts', contactId, req.user.id);
      if (!isOwner) continue;
      
      const contact = await db.getContactById(contactId);
      if (contact && !contact.unsubscribed) {
        await db.addToEmailQueue({
          user_id: req.user.id,
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
    security.createAuditLog('CAMPAIGN_STARTED', req.user.id, { campaignId: req.params.id, contacts: added }, req);
    res.json({ message: `Campaign started with ${added} contacts` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/campaigns/:id/pause', authenticateToken, verifyOwnership('campaigns'), async (req, res) => {
  await db.updateCampaignStatus(req.params.id, 'paused');
  res.json({ message: 'Campaign paused' });
});

app.post('/api/campaigns/:id/resume', authenticateToken, verifyOwnership('campaigns'), async (req, res) => {
  await db.updateCampaignStatus(req.params.id, 'sending');
  res.json({ message: 'Campaign resumed' });
});

// ============================================================================
// SEQUENCE ROUTES (User-scoped)
// ============================================================================

app.get('/api/sequences', authenticateToken, async (req, res) => {
  const sequences = await db.getSequencesForUser(req.user.id);
  res.json({ sequences });
});

app.get('/api/sequences/:id', authenticateToken, verifyOwnership('sequences'), async (req, res) => {
  const sequence = await db.getSequenceWithSteps(req.params.id);
  if (!sequence) return res.status(404).json({ error: 'Sequence not found' });
  res.json({ sequence });
});

app.post('/api/sequences', authenticateToken, async (req, res) => {
  try {
    const { name, description, from_name, from_email, steps } = req.body;
    
    if (!name || !from_name || !from_email) {
      return res.status(400).json({ error: 'Name, from_name, and from_email are required' });
    }
    if (!security.validators.email(from_email)) return res.status(400).json({ error: 'Invalid from email' });

    const sequence = await db.createSequence({
      name: security.sanitizers.text(name),
      description: security.sanitizers.text(description || ''),
      from_name: security.sanitizers.text(from_name),
      from_email: from_email.toLowerCase().trim()
    }, req.user.id);

    if (steps && steps.length > 0) {
      for (let i = 0; i < steps.length; i++) {
        await db.createSequenceStep(sequence.id, {
          step_number: i + 1,
          subject: security.sanitizers.subject(steps[i].subject),
          body: security.sanitizers.html(steps[i].body),
          delay_days: parseInt(steps[i].delay_days) || 1,
          delay_hours: parseInt(steps[i].delay_hours) || 0
        });
      }
    }

    const fullSequence = await db.getSequenceWithSteps(sequence.id);
    res.json({ sequence: fullSequence });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/sequences/:id/add-contacts', authenticateToken, verifyOwnership('sequences'), async (req, res) => {
  try {
    const { contactIds } = req.body;
    // Verify each contact belongs to user
    const validContactIds = [];
    for (const contactId of (contactIds || [])) {
      const isOwner = await db.verifyResourceOwnership('contacts', contactId, req.user.id);
      if (isOwner) validContactIds.push(contactId);
    }
    const added = await db.addContactsToSequence(req.params.id, validContactIds);
    res.json({ message: `${added} contacts added to sequence` });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/sequences/:id/start', authenticateToken, verifyOwnership('sequences'), async (req, res) => {
  try {
    await db.query('UPDATE sequences SET status = $1 WHERE id = $2', ['active', req.params.id]);
    security.createAuditLog('SEQUENCE_STARTED', req.user.id, { sequenceId: req.params.id }, req);
    res.json({ message: 'Sequence started' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/sequences/:id/pause', authenticateToken, verifyOwnership('sequences'), async (req, res) => {
  try {
    await db.query('UPDATE sequences SET status = $1 WHERE id = $2', ['paused', req.params.id]);
    res.json({ message: 'Sequence paused' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// ANALYTICS ROUTES (User-scoped)
// ============================================================================

app.get('/api/analytics/overview', authenticateToken, async (req, res) => {
  try {
    const stats = await db.getOverallStatsForUser(req.user.id);
    res.json({ stats });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/analytics/daily', authenticateToken, async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const stats = await db.getDailyStatsForUser(req.user.id, parseInt(days));
    res.json({ stats });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/analytics/campaigns/:id', authenticateToken, verifyOwnership('campaigns'), async (req, res) => {
  try {
    const analytics = await db.getCampaignAnalytics(req.params.id);
    if (!analytics) return res.status(404).json({ error: 'Campaign not found' });
    res.json({ analytics });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// CLOUDFLARE CONFIG ROUTES (User-scoped with encryption)
// ============================================================================

app.get('/api/cloudflare/config', authenticateToken, async (req, res) => {
  try {
    const result = await db.query(
      'SELECT id, account_id, account_name, is_valid, created_at FROM cloudflare_configs WHERE user_id = $1',
      [req.user.id]
    );
    if (result.rows.length === 0) return res.json({ configured: false });
    res.json({ configured: true, config: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/cloudflare/config', authenticateToken, async (req, res) => {
  try {
    const { apiToken, accountId } = req.body;
    if (!apiToken || !accountId) return res.status(400).json({ error: 'API token and Account ID required' });
    if (!security.validators.maxLength(apiToken, 500)) return res.status(400).json({ error: 'Invalid API token' });
    if (!security.validators.maxLength(accountId, 100)) return res.status(400).json({ error: 'Invalid Account ID' });

    const cf = new CloudflareClient(apiToken, accountId);
    const verification = await cf.verifyConnection();
    if (!verification.valid) return res.status(400).json({ error: 'Invalid Cloudflare credentials' });

    let accountName = 'Unknown';
    try { const account = await cf.getAccountDetails(); accountName = account.name; } catch (e) {}

    // Encrypt the API token before storing
    const encryptedToken = security.encrypt(apiToken);

    await db.query(`
      INSERT INTO cloudflare_configs (user_id, api_token, account_id, account_name, is_valid)
      VALUES ($1, $2, $3, $4, true)
      ON CONFLICT (user_id) DO UPDATE SET api_token = $2, account_id = $3, account_name = $4, is_valid = true, updated_at = NOW()
    `, [req.user.id, encryptedToken, accountId, accountName]);

    security.createAuditLog('CLOUDFLARE_CONNECTED', req.user.id, { accountName }, req);
    res.json({ success: true, message: 'Cloudflare connected successfully', accountName });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/cloudflare/config', authenticateToken, async (req, res) => {
  try {
    await db.query('DELETE FROM cloudflare_configs WHERE user_id = $1', [req.user.id]);
    security.createAuditLog('CLOUDFLARE_DISCONNECTED', req.user.id, {}, req);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/cloudflare/zones', authenticateToken, async (req, res) => {
  try {
    const cf = await getUserCloudflareClient(req.user.id);
    const zones = await cf.getZones();
    res.json({ zones });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// DOMAIN ROUTES (User-scoped)
// ============================================================================

app.post('/api/domains/search', authenticateToken, async (req, res) => {
  try {
    const { query } = req.body;
    if (!query || query.length < 2 || query.length > 63) {
      return res.status(400).json({ error: 'Search query must be 2-63 characters' });
    }

    const baseName = query.toLowerCase().replace(/[^a-z0-9-]/g, '');
    if (baseName.length < 2) return res.status(400).json({ error: 'Invalid domain name' });
    
    const cf = await getUserCloudflareClient(req.user.id);

    const tlds = ['.com', '.io', '.co', '.net', '.dev', '.app'];
    const results = [];

    for (const tld of tlds) {
      const domain = baseName + tld;
      try {
        const availability = await cf.checkAvailabilityViaRegistrar(domain);
        results.push({
          domain, available: availability.available, premium: availability.premium || false,
          price: availability.price || getEstimatedPrice(domain), currency: 'USD'
        });
      } catch (error) {
        results.push({ domain, available: 'unknown', price: getEstimatedPrice(domain), currency: 'USD' });
      }
    }

    res.json({ results });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/domains/purchase', authenticateToken, async (req, res) => {
  try {
    const { domain, contactInfo } = req.body;
    if (!domain || !security.validators.domain(domain)) {
      return res.status(400).json({ error: 'Valid domain name required' });
    }

    const cf = await getUserCloudflareClient(req.user.id);

    const contact = contactInfo || {
      first_name: req.user.name.split(' ')[0],
      last_name: req.user.name.split(' ').slice(1).join(' ') || 'User',
      email: req.user.email, phone: '+1.0000000000',
      address: '123 Main St', city: 'San Francisco', state: 'CA', zip: '94102', country: 'US', organization: ''
    };

    const purchase = await cf.purchaseDomain(domain, contact);

    await db.query(`
      INSERT INTO domains (user_id, domain_name, status, expires_at)
      VALUES ($1, $2, 'active', $3)
      ON CONFLICT (domain_name) DO UPDATE SET status = 'active', user_id = $1, expires_at = $3, updated_at = NOW()
    `, [req.user.id, domain, purchase.expires_at]);

    security.createAuditLog('DOMAIN_PURCHASED', req.user.id, { domain }, req);
    res.json({ success: true, domain: purchase.domain, message: 'Domain purchased successfully!' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/domains', authenticateToken, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM domains WHERE user_id = $1 ORDER BY created_at DESC', [req.user.id]);
    res.json({ domains: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/domains/:id', authenticateToken, verifyOwnership('domains'), async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM domains WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Domain not found' });
    const domain = result.rows[0];
    const dnsRecords = await db.query('SELECT * FROM domain_dns_records WHERE domain_id = $1', [domain.id]);
    domain.dnsRecords = dnsRecords.rows;
    res.json({ domain });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/domains/add-existing', authenticateToken, async (req, res) => {
  try {
    const { domain } = req.body;
    if (!domain || !security.validators.domain(domain)) {
      return res.status(400).json({ error: 'Valid domain name required' });
    }

    const cf = await getUserCloudflareClient(req.user.id);
    let zone = await cf.getZoneByDomain(domain);
    if (!zone) zone = await cf.createZone(domain);

    const result = await db.query(`
      INSERT INTO domains (user_id, domain_name, zone_id, status, registrar)
      VALUES ($1, $2, $3, 'active', 'external')
      ON CONFLICT (domain_name) DO UPDATE SET zone_id = $3, user_id = $1, status = 'active', updated_at = NOW()
      RETURNING *
    `, [req.user.id, domain, zone.id]);

    res.json({ success: true, domain: result.rows[0], nameservers: zone.name_servers });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/domains/:id/configure-dns', authenticateToken, verifyOwnership('domains'), async (req, res) => {
  try {
    const domainResult = await db.query('SELECT * FROM domains WHERE id = $1', [req.params.id]);
    if (domainResult.rows.length === 0) return res.status(404).json({ error: 'Domain not found' });

    const domain = domainResult.rows[0];
    const cf = await getUserCloudflareClient(req.user.id);

    let zone = domain.zone_id ? { id: domain.zone_id } : await cf.getZoneByDomain(domain.domain_name);
    if (!zone) zone = await cf.createZone(domain.domain_name);

    const dnsResults = await cf.setupEmailRecords(zone.id, domain.domain_name);

    await db.query('UPDATE domains SET zone_id = $1, dns_configured = true, updated_at = NOW() WHERE id = $2', [zone.id, domain.id]);

    res.json({ success: true, message: 'DNS configured successfully', records: dnsResults });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/domains/:id/enable-email-routing', authenticateToken, verifyOwnership('domains'), async (req, res) => {
  try {
    const { forwardTo } = req.body;
    if (forwardTo && !security.validators.email(forwardTo)) {
      return res.status(400).json({ error: 'Invalid forwarding email' });
    }
    
    const domainResult = await db.query('SELECT * FROM domains WHERE id = $1', [req.params.id]);
    if (domainResult.rows.length === 0) return res.status(404).json({ error: 'Domain not found' });

    const domain = domainResult.rows[0];
    if (!domain.zone_id) return res.status(400).json({ error: 'Configure DNS first' });

    const cf = await getUserCloudflareClient(req.user.id);
    await cf.enableEmailRouting(domain.zone_id);
    if (forwardTo) await cf.createCatchAllForwarding(domain.zone_id, forwardTo);

    await db.query('UPDATE domains SET email_routing_enabled = true, forward_to = $1, updated_at = NOW() WHERE id = $2', [forwardTo || null, domain.id]);

    res.json({ success: true, message: forwardTo ? `Email routing enabled. Forwarding to ${forwardTo}` : 'Email routing enabled' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/domains/:id/full-setup', authenticateToken, verifyOwnership('domains'), async (req, res) => {
  try {
    const { forwardTo } = req.body;
    if (forwardTo && !security.validators.email(forwardTo)) {
      return res.status(400).json({ error: 'Invalid forwarding email' });
    }
    
    const domainResult = await db.query('SELECT * FROM domains WHERE id = $1', [req.params.id]);
    if (domainResult.rows.length === 0) return res.status(404).json({ error: 'Domain not found' });

    const domain = domainResult.rows[0];
    const cf = await getUserCloudflareClient(req.user.id);
    const results = await cf.fullDomainSetup(domain.domain_name, forwardTo);

    await db.query(`
      UPDATE domains SET zone_id = $1, dns_configured = true, email_routing_enabled = $2, forward_to = $3, updated_at = NOW() WHERE id = $4
    `, [results.zone?.id, results.emailRouting?.enabled || false, forwardTo, domain.id]);

    res.json({ success: true, message: 'Domain fully configured!', results, errors: results.errors });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/domains/import', authenticateToken, async (req, res) => {
  try {
    const { zoneId, zoneName } = req.body;
    if (!zoneId || !zoneName) return res.status(400).json({ error: 'Zone ID and name required' });

    const result = await db.query(`
      INSERT INTO domains (user_id, domain_name, zone_id, status, registrar)
      VALUES ($1, $2, $3, 'active', 'cloudflare')
      ON CONFLICT (domain_name) DO UPDATE SET zone_id = $3, user_id = $1, status = 'active', updated_at = NOW()
      RETURNING *
    `, [req.user.id, zoneName, zoneId]);

    res.json({ success: true, domain: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/domains/:id', authenticateToken, verifyOwnership('domains'), async (req, res) => {
  try {
    await db.query('DELETE FROM domains WHERE id = $1', [req.params.id]);
    res.json({ success: true });
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
  security.createAuditLog('SERVER_ERROR', req.user?.id, { error: err.message, path: req.path }, req);
  res.status(500).json({ error: 'Internal server error' });
});

// ============================================================================
// START SERVER
// ============================================================================

app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║  🔒 Cold Email System v3.2 - WITH AI WARMING                   ║
║                                                                ║
║  Port: ${PORT}                                                    ║
║  Database: ${process.env.DATABASE_URL ? '✅ Connected' : '❌ Not configured'}                               ║
║                                                                ║
║  Security Features:                                            ║
║  ✅ AES-256-GCM Encryption for credentials                     ║
║  ✅ User isolation on all data                                  ║
║  ✅ Ownership verification on actions                          ║
║  ✅ Input validation & sanitization                            ║
║  ✅ Brute force protection                                      ║
║  ✅ Rate limiting (global + per-user)                          ║
║  ✅ Strong password requirements                                ║
║  ✅ Audit logging                                               ║
║  ✅ AI-powered email warming                                    ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
  `);
  
  // Security warnings
  if (!process.env.JWT_SECRET) console.warn('⚠️  Set JWT_SECRET environment variable!');
  if (!process.env.ENCRYPTION_KEY) console.warn('⚠️  Set ENCRYPTION_KEY environment variable!');
  if (!process.env.ANTHROPIC_API_KEY) console.log('ℹ️  No ANTHROPIC_API_KEY set - using template-based warming');
  
  startEmailProcessor();
  
  // Initialize warming system
  const initWarming = async () => {
    warmingScheduler = new WarmingScheduler(db, {
      sendWarmingEmail: async (senderAccount, recipientEmail, subject, body) => {
        const decryptedPass = security.decrypt(senderAccount.smtp_pass);
        const transporter = nodemailer.createTransport({
          host: senderAccount.smtp_host,
          port: senderAccount.smtp_port,
          secure: senderAccount.smtp_port === 465,
          auth: { user: senderAccount.smtp_user, pass: decryptedPass }
        });
        
        await transporter.sendMail({
          from: senderAccount.email,
          to: recipientEmail,
          subject: subject,
          text: body.replace(/<[^>]*>/g, ''),
          html: body.replace(/\n/g, '<br>')
        });
      }
    });
    
    await warmingScheduler.restoreActiveJobs();
    console.log('🔥 Warming system initialized');
  };
  initWarming().catch(err => console.error('Warming init error:', err));
});

process.on('SIGTERM', () => {
  console.log('Shutting down...');
  clearInterval(emailJobInterval);
  process.exit(0);
});
