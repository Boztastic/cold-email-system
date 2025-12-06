require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { pool, initializeDatabase } = require('./database');
const { Resend } = require('resend');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Initialize Resend
const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

// Middleware
app.use(cors());
app.use(express.json());

// Audit logging
function auditLog(action, userId, ip, userAgent, details) {
  console.log(`AUDIT: ${JSON.stringify({ timestamp: new Date().toISOString(), action, userId, ip, userAgent, details })}`);
  pool.query(
    'INSERT INTO audit_log (user_id, action, ip_address, user_agent, details) VALUES ($1, $2, $3, $4, $5)',
    [userId, action, ip, userAgent, details]
  ).catch(err => console.error('Audit log error:', err));
}

// Auth middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// ============================================
// AUTH ROUTES
// ============================================

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, companyName } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, company_name) VALUES ($1, $2, $3) RETURNING id, email, company_name',
      [email, hashedPassword, companyName]
    );
    
    const token = jwt.sign({ userId: result.rows[0].id, email }, JWT_SECRET, { expiresIn: '7d' });
    
    // Initialize warming status
    await pool.query('INSERT INTO warming_status (user_id) VALUES ($1)', [result.rows[0].id]);
    
    auditLog('USER_REGISTERED', result.rows[0].id, req.ip, req.headers['user-agent'], { email });
    
    res.json({ token, user: result.rows[0] });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(400).json({ error: 'Email already exists' });
    }
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    
    auditLog('USER_LOGIN', user.id, req.ip, req.headers['user-agent'], { email });
    
    res.json({ token, user: { id: user.id, email: user.email, company_name: user.company_name } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ============================================
// DOMAIN ROUTES - Auto-import from Cloudflare
// ============================================

// List domains from Cloudflare (available to import)
app.get('/api/cloudflare/domains', authenticateToken, async (req, res) => {
  try {
    if (!CF_API_TOKEN) {
      return res.status(400).json({ error: 'Cloudflare API not configured' });
    }
    
    // Get all zones from Cloudflare
    const zonesResponse = await fetch(`${CF_API}/zones?per_page=50`, {
      headers: { 'Authorization': `Bearer ${CF_API_TOKEN}` }
    });
    const zonesData = await zonesResponse.json();
    
    if (!zonesData.success) {
      return res.status(400).json({ error: 'Failed to fetch from Cloudflare', details: zonesData.errors });
    }
    
    // Get already imported domains for this user
    const imported = await pool.query(
      'SELECT domain_name FROM domains WHERE user_id = $1',
      [req.user.userId]
    );
    const importedNames = imported.rows.map(d => d.domain_name);
    
    // Map and mark which are already imported
    const domains = zonesData.result.map(zone => ({
      id: zone.id,
      name: zone.name,
      status: zone.status,
      imported: importedNames.includes(zone.name)
    }));
    
    res.json({ domains });
  } catch (error) {
    console.error('Fetch Cloudflare domains error:', error);
    res.status(500).json({ error: 'Failed to fetch domains' });
  }
});

// Import domain from Cloudflare - one click full setup
app.post('/api/domains/import', authenticateToken, async (req, res) => {
  try {
    const { zoneId, domainName } = req.body;
    
    if (!zoneId || !domainName) {
      return res.status(400).json({ error: 'Zone ID and domain name required' });
    }
    
    const cleanDomain = domainName.toLowerCase().trim();
    let setupLog = [];
    
    // Check if already exists
    const existing = await pool.query(
      'SELECT id FROM domains WHERE user_id = $1 AND domain_name = $2',
      [req.user.userId, cleanDomain]
    );
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Domain already imported' });
    }
    
    setupLog.push({ step: 'Cloudflare', status: 'success', message: `Zone ${zoneId.substring(0, 8)}...` });
    
    // Step 1: Insert domain
    const result = await pool.query(
      `INSERT INTO domains (user_id, domain_name, cloudflare_zone_id, verification_status, warming_enabled) 
       VALUES ($1, $2, $3, 'pending', false) RETURNING *`,
      [req.user.userId, cleanDomain, zoneId]
    );
    const domainId = result.rows[0].id;
    
    // Step 2: Create email accounts
    const prefixes = ['team', 'hello', 'contact', 'info'];
    for (const prefix of prefixes) {
      await pool.query(
        'INSERT INTO email_accounts (user_id, domain_id, email_address, display_name, account_type) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING',
        [req.user.userId, domainId, `${prefix}@${cleanDomain}`, `${prefix.charAt(0).toUpperCase() + prefix.slice(1)} Team`, 'warming']
      );
    }
    setupLog.push({ step: 'Email Accounts', status: 'success', message: '4 accounts created' });
    
    // Step 3: Add to Resend
    let resendDomainId = null;
    let resendRecords = [];
    
    if (resend) {
      try {
        const resendDomain = await resend.domains.create({ name: cleanDomain });
        resendDomainId = resendDomain.data?.id;
        
        if (resendDomainId) {
          const domainDetails = await resend.domains.get(resendDomainId);
          resendRecords = domainDetails.data?.records || [];
          
          await pool.query(
            'UPDATE domains SET resend_domain_id = $1, warming_enabled = true WHERE id = $2',
            [resendDomainId, domainId]
          );
          setupLog.push({ step: 'Resend', status: 'success', message: 'Sending enabled' });
        }
      } catch (err) {
        if (err.message?.includes('already exists')) {
          // Try to get existing domain from Resend
          try {
            const existingDomains = await resend.domains.list();
            const found = existingDomains.data?.data?.find(d => d.name === cleanDomain);
            if (found) {
              resendDomainId = found.id;
              const domainDetails = await resend.domains.get(resendDomainId);
              resendRecords = domainDetails.data?.records || [];
              await pool.query(
                'UPDATE domains SET resend_domain_id = $1, warming_enabled = true WHERE id = $2',
                [resendDomainId, domainId]
              );
              setupLog.push({ step: 'Resend', status: 'success', message: 'Using existing domain' });
            }
          } catch (e) {
            setupLog.push({ step: 'Resend', status: 'warning', message: 'Domain exists, configure manually' });
          }
        } else {
          setupLog.push({ step: 'Resend', status: 'error', message: err.message });
        }
      }
    } else {
      setupLog.push({ step: 'Resend', status: 'error', message: 'API not configured' });
    }
    
    // Step 4: Add DNS records to Cloudflare
    let dnsAdded = 0;
    let dnsExisted = 0;
    
    if (CF_API_TOKEN && resendRecords.length > 0) {
      for (const record of resendRecords) {
        try {
          const cfResponse = await fetch(`${CF_API}/zones/${zoneId}/dns_records`, {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${CF_API_TOKEN}`,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              type: record.record_type || record.type,
              name: record.name,
              content: record.value,
              ttl: 3600,
              priority: record.priority || undefined
            })
          });
          const cfResult = await cfResponse.json();
          if (cfResult.success) {
            dnsAdded++;
          } else if (cfResult.errors?.[0]?.message?.includes('already exists')) {
            dnsExisted++;
          }
        } catch (err) {
          // Continue with other records
        }
      }
      setupLog.push({ 
        step: 'DNS Records', 
        status: 'success', 
        message: `${dnsAdded} added, ${dnsExisted} already existed` 
      });
    }
    
    // Step 5: Enable email routing
    if (CF_API_TOKEN) {
      try {
        await fetch(`${CF_API}/zones/${zoneId}/email/routing/enable`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${CF_API_TOKEN}` }
        });
        setupLog.push({ step: 'Email Routing', status: 'success', message: 'Enabled' });
      } catch (err) {
        setupLog.push({ step: 'Email Routing', status: 'warning', message: err.message });
      }
    }
    
    // Step 6: Check Resend verification (after DNS propagation)
    if (resendDomainId) {
      try {
        // Wait a moment for DNS
        await new Promise(r => setTimeout(r, 2000));
        
        const verifyResponse = await resend.domains.verify(resendDomainId);
        const checkResponse = await resend.domains.get(resendDomainId);
        const isVerified = checkResponse.data?.status === 'verified';
        
        await pool.query(
          'UPDATE domains SET resend_verified = $1, verification_status = $2 WHERE id = $3',
          [isVerified, isVerified ? 'verified' : 'pending', domainId]
        );
        
        setupLog.push({ 
          step: 'Verification', 
          status: isVerified ? 'success' : 'pending', 
          message: isVerified ? 'Domain verified!' : 'Pending - check back in a few minutes' 
        });
      } catch (err) {
        setupLog.push({ step: 'Verification', status: 'pending', message: 'Will verify shortly' });
      }
    }
    
    // Step 7: Deploy Email Worker for inbox
    let inboxEnabled = false;
    if (CF_API_TOKEN && CF_ACCOUNT_ID) {
      try {
        const webhookSecret = crypto.randomBytes(32).toString('hex');
        const workerName = `email-inbox-${cleanDomain.replace(/\./g, '-')}`;
        const webhookUrl = `${WEBHOOK_BASE_URL}/api/webhook/email-receive`;
        
        // Deploy worker
        const workerScript = generateEmailWorkerScript(webhookUrl, webhookSecret);
        const workerResponse = await fetch(
          `${CF_API}/accounts/${CF_ACCOUNT_ID}/workers/scripts/${workerName}`,
          {
            method: 'PUT',
            headers: {
              'Authorization': `Bearer ${CF_API_TOKEN}`,
              'Content-Type': 'application/javascript'
            },
            body: workerScript
          }
        );
        
        if (workerResponse.ok) {
          // Create catch-all rule to worker
          await fetch(`${CF_API}/zones/${zoneId}/email/routing/rules`, {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${CF_API_TOKEN}`,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({
              name: 'Inbox catch-all',
              enabled: true,
              matchers: [{ type: 'all' }],
              actions: [{ type: 'worker', value: [workerName] }]
            })
          });
          
          await pool.query(
            'UPDATE domains SET inbox_enabled = true, webhook_secret = $1 WHERE id = $2',
            [webhookSecret, domainId]
          );
          inboxEnabled = true;
          setupLog.push({ step: 'Inbox', status: 'success', message: 'Email worker deployed' });
        } else {
          setupLog.push({ step: 'Inbox', status: 'warning', message: 'Worker deployment failed' });
        }
      } catch (err) {
        setupLog.push({ step: 'Inbox', status: 'warning', message: err.message });
      }
    } else {
      setupLog.push({ step: 'Inbox', status: 'skipped', message: 'Configure CLOUDFLARE_ACCOUNT_ID' });
    }
    
    auditLog('DOMAIN_IMPORTED', req.user.userId, req.ip, req.headers['user-agent'], { 
      domainName: cleanDomain, 
      setupLog 
    });
    
    console.log(`✅ Domain imported: ${cleanDomain}`, setupLog);
    
    res.json({ 
      success: true, 
      domain: { ...result.rows[0], inbox_enabled: inboxEnabled },
      setupLog 
    });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(400).json({ error: 'Domain already exists' });
    }
    console.error('Import domain error:', error);
    res.status(500).json({ error: error.message || 'Failed to import domain' });
  }
});

// Get user's imported domains
app.get('/api/domains', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM domains WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get domains error:', error);
    res.status(500).json({ error: 'Failed to get domains' });
  }
});

// Refresh domain status
app.post('/api/domains/:id/refresh', authenticateToken, async (req, res) => {
  try {
    const domain = await pool.query(
      'SELECT * FROM domains WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.userId]
    );
    
    if (domain.rows.length === 0) {
      return res.status(404).json({ error: 'Domain not found' });
    }
    
    const d = domain.rows[0];
    let updates = {};
    
    // Check Resend verification
    if (d.resend_domain_id && resend) {
      try {
        const resendDomain = await resend.domains.get(d.resend_domain_id);
        updates.resend_verified = resendDomain.data?.status === 'verified';
        updates.verification_status = updates.resend_verified ? 'verified' : 'pending';
      } catch (err) {
        console.error('Resend check error:', err);
      }
    }
    
    if (Object.keys(updates).length > 0) {
      const setClauses = Object.keys(updates).map((k, i) => `${k} = $${i + 1}`).join(', ');
      const values = [...Object.values(updates), req.params.id];
      await pool.query(`UPDATE domains SET ${setClauses} WHERE id = $${values.length}`, values);
    }
    
    const updated = await pool.query('SELECT * FROM domains WHERE id = $1', [req.params.id]);
    res.json({ success: true, domain: updated.rows[0] });
  } catch (error) {
    console.error('Refresh domain error:', error);
    res.status(500).json({ error: 'Failed to refresh' });
  }
});

// Delete domain
app.delete('/api/domains/:id', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM domains WHERE id = $1 AND user_id = $2', [req.params.id, req.user.userId]);
    res.json({ success: true });
  } catch (error) {
    console.error('Delete domain error:', error);
    res.status(500).json({ error: 'Failed to delete domain' });
  }
});

// ============================================
// EMAIL ACCOUNTS ROUTES
// ============================================

app.get('/api/email-accounts', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ea.*, d.domain_name, d.resend_verified 
       FROM email_accounts ea 
       JOIN domains d ON ea.domain_id = d.id 
       WHERE ea.user_id = $1 
       ORDER BY d.domain_name, ea.email_address`,
      [req.user.userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get email accounts error:', error);
    res.status(500).json({ error: 'Failed to get email accounts' });
  }
});

// ============================================
// WARMING ROUTES
// ============================================

app.get('/api/warming/status', authenticateToken, async (req, res) => {
  try {
    const status = await pool.query('SELECT * FROM warming_status WHERE user_id = $1', [req.user.userId]);
    
    // Get stats
    const stats = await pool.query(`
      SELECT 
        COUNT(*) as total_sent,
        COUNT(*) FILTER (WHERE is_ai_generated = true) as ai_generated,
        COUNT(*) FILTER (WHERE status = 'replied') as replies
      FROM warming_emails 
      WHERE user_id = $1 AND created_at > NOW() - INTERVAL '30 days'
    `, [req.user.userId]);
    
    // Get recent emails
    const recent = await pool.query(`
      SELECT from_email, to_email, subject, status, is_ai_generated, created_at
      FROM warming_emails 
      WHERE user_id = $1 
      ORDER BY created_at DESC 
      LIMIT 10
    `, [req.user.userId]);
    
    res.json({
      status: status.rows[0] || { is_active: false, emails_per_day: 10 },
      stats: stats.rows[0],
      recentEmails: recent.rows
    });
  } catch (error) {
    console.error('Get warming status error:', error);
    res.status(500).json({ error: 'Failed to get warming status' });
  }
});

app.post('/api/warming/start', authenticateToken, async (req, res) => {
  try {
    const { emailsPerDay = 10, aiFrequency = 0.3 } = req.body;
    
    await pool.query(`
      INSERT INTO warming_status (user_id, is_active, emails_per_day, ai_frequency, updated_at) 
      VALUES ($1, true, $2, $3, NOW())
      ON CONFLICT (user_id) 
      DO UPDATE SET is_active = true, emails_per_day = $2, ai_frequency = $3, updated_at = NOW()
    `, [req.user.userId, emailsPerDay, aiFrequency]);
    
    console.log(`🔥 Warming started for user ${req.user.userId}: ${emailsPerDay} emails/day`);
    auditLog('WARMING_STARTED', req.user.userId, req.ip, req.headers['user-agent'], { emailsPerDay, aiFrequency });
    
    res.json({ success: true });
  } catch (error) {
    console.error('Start warming error:', error);
    res.status(500).json({ error: 'Failed to start warming' });
  }
});

app.post('/api/warming/stop', authenticateToken, async (req, res) => {
  try {
    await pool.query('UPDATE warming_status SET is_active = false, updated_at = NOW() WHERE user_id = $1', [req.user.userId]);
    
    console.log(`🔥 Warming stopped for user ${req.user.userId}`);
    auditLog('WARMING_STOPPED', req.user.userId, req.ip, req.headers['user-agent'], {});
    
    res.json({ success: true });
  } catch (error) {
    console.error('Stop warming error:', error);
    res.status(500).json({ error: 'Failed to stop warming' });
  }
});

app.put('/api/warming/config', authenticateToken, async (req, res) => {
  try {
    const { emailsPerDay, aiFrequency } = req.body;
    
    await pool.query(
      'UPDATE warming_status SET emails_per_day = $1, ai_frequency = $2, updated_at = NOW() WHERE user_id = $3',
      [emailsPerDay, aiFrequency, req.user.userId]
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Update warming config error:', error);
    res.status(500).json({ error: 'Failed to update config' });
  }
});

// ============================================
// CLOUDFLARE EMAIL WORKER SETUP
// ============================================

const CF_API = 'https://api.cloudflare.com/client/v4';
const CF_API_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
const CF_ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID;
const WEBHOOK_BASE_URL = process.env.WEBHOOK_BASE_URL || 'https://your-backend.onrender.com';

// Generate the Email Worker script
function generateEmailWorkerScript(webhookUrl, webhookSecret) {
  return `
export default {
  async email(message, env, ctx) {
    try {
      // Read email body
      const reader = message.raw.getReader();
      const chunks = [];
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
      }
      const rawEmail = new TextDecoder().decode(new Uint8Array(chunks.flat()));
      
      // Extract text body (simple extraction)
      let textBody = '';
      const lines = rawEmail.split('\\n');
      let inBody = false;
      for (const line of lines) {
        if (inBody) textBody += line + '\\n';
        if (line.trim() === '') inBody = true;
      }
      
      // Send to webhook
      await fetch('${webhookUrl}', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Webhook-Secret': '${webhookSecret}'
        },
        body: JSON.stringify({
          from: message.from,
          to: message.to,
          subject: message.headers.get('subject') || '(no subject)',
          body: textBody.trim().substring(0, 10000),
          messageId: message.headers.get('message-id'),
          date: message.headers.get('date')
        })
      });
    } catch (error) {
      console.error('Email worker error:', error);
    }
  }
}`;
}

// Deploy Email Worker to Cloudflare
async function deployEmailWorker(zoneId, domainName, userId) {
  if (!CF_API_TOKEN || !CF_ACCOUNT_ID) {
    throw new Error('Cloudflare API credentials not configured');
  }
  
  const webhookSecret = crypto.randomBytes(32).toString('hex');
  const workerName = `email-inbox-${domainName.replace(/\./g, '-')}`;
  const webhookUrl = `${WEBHOOK_BASE_URL}/api/webhook/email-receive`;
  
  // Store webhook secret for this domain
  await pool.query(
    'UPDATE domains SET webhook_secret = $1 WHERE cloudflare_zone_id = $2',
    [webhookSecret, zoneId]
  );
  
  // 1. Deploy the worker script
  const workerScript = generateEmailWorkerScript(webhookUrl, webhookSecret);
  
  const workerResponse = await fetch(
    `${CF_API}/accounts/${CF_ACCOUNT_ID}/workers/scripts/${workerName}`,
    {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${CF_API_TOKEN}`,
        'Content-Type': 'application/javascript'
      },
      body: workerScript
    }
  );
  
  if (!workerResponse.ok) {
    const err = await workerResponse.json();
    throw new Error(`Worker deploy failed: ${JSON.stringify(err)}`);
  }
  
  // 2. Enable Email Routing on the zone
  await fetch(`${CF_API}/zones/${zoneId}/email/routing/enable`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${CF_API_TOKEN}`,
      'Content-Type': 'application/json'
    }
  });
  
  // 3. Create catch-all rule to send to worker
  const ruleResponse = await fetch(`${CF_API}/zones/${zoneId}/email/routing/rules`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${CF_API_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      name: 'Catch-all to inbox worker',
      enabled: true,
      matchers: [{ type: 'all' }],
      actions: [{ type: 'worker', value: [workerName] }]
    })
  });
  
  if (!ruleResponse.ok) {
    const err = await ruleResponse.json();
    console.error('Rule creation failed:', err);
    // Rule might already exist, continue anyway
  }
  
  console.log(`📬 Email Worker deployed for ${domainName}`);
  return { workerName, webhookSecret };
}

// Enable inbox on domain
app.post('/api/domains/:id/enable-inbox', authenticateToken, async (req, res) => {
  try {
    const domain = await pool.query(
      'SELECT * FROM domains WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.userId]
    );
    
    if (domain.rows.length === 0) {
      return res.status(404).json({ error: 'Domain not found' });
    }
    
    const d = domain.rows[0];
    
    if (!d.cloudflare_zone_id) {
      return res.status(400).json({ error: 'Domain needs Cloudflare Zone ID' });
    }
    
    // Deploy Email Worker
    const result = await deployEmailWorker(d.cloudflare_zone_id, d.domain_name, req.user.userId);
    
    // Update domain
    await pool.query(
      'UPDATE domains SET inbox_enabled = true WHERE id = $1',
      [req.params.id]
    );
    
    auditLog('INBOX_ENABLED', req.user.userId, req.ip, req.headers['user-agent'], { 
      domain: d.domain_name 
    });
    
    res.json({ 
      success: true, 
      message: 'Email inbox enabled! Emails will now be received.',
      workerName: result.workerName
    });
  } catch (error) {
    console.error('Enable inbox error:', error);
    res.status(500).json({ error: error.message || 'Failed to enable inbox' });
  }
});

// Webhook to receive emails from Cloudflare Worker
app.post('/api/webhook/email-receive', async (req, res) => {
  try {
    const webhookSecret = req.headers['x-webhook-secret'];
    const { from, to, subject, body, messageId, date } = req.body;
    
    if (!from || !to) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Find domain by webhook secret
    const domain = await pool.query(
      'SELECT d.*, u.id as owner_id FROM domains d JOIN users u ON d.user_id = u.id WHERE d.webhook_secret = $1',
      [webhookSecret]
    );
    
    if (domain.rows.length === 0) {
      console.log('⚠️ Unknown webhook secret for incoming email');
      return res.status(401).json({ error: 'Invalid webhook secret' });
    }
    
    const d = domain.rows[0];
    
    // Check if this is a warming email reply (match thread)
    const existingThread = await pool.query(
      'SELECT thread_id FROM inbox_messages WHERE user_id = $1 AND (from_email = $2 OR to_email = $2) ORDER BY created_at DESC LIMIT 1',
      [d.owner_id, from]
    );
    
    const threadId = existingThread.rows[0]?.thread_id || generateThreadId();
    const isWarming = from.endsWith(d.domain_name) || to.endsWith(d.domain_name);
    
    // Store in inbox
    await pool.query(`
      INSERT INTO inbox_messages (user_id, message_type, from_email, to_email, subject, body, thread_id, is_warming, is_read)
      VALUES ($1, 'received', $2, $3, $4, $5, $6, $7, false)
    `, [d.owner_id, from, to, subject, body, threadId, isWarming]);
    
    // Update thread
    await createOrUpdateThread(d.owner_id, threadId, subject, [from, to], isWarming);
    
    console.log(`📥 Email received: ${from} → ${to} (${subject})`);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Email webhook error:', error);
    res.status(500).json({ error: 'Failed to process email' });
  }
});

// ============================================
// INBOX ROUTES - View warming activity
// ============================================

// Get all messages (flat view)
app.get('/api/inbox', authenticateToken, async (req, res) => {
  try {
    const { filter = 'all', limit = 50 } = req.query;
    
    let query = `
      SELECT im.*, 
        (SELECT COUNT(*) FROM inbox_messages im2 WHERE im2.thread_id = im.thread_id AND im2.user_id = $1) as thread_count
      FROM inbox_messages im
      WHERE im.user_id = $1
    `;
    
    if (filter === 'unread') {
      query += ' AND im.is_read = false';
    } else if (filter === 'warming') {
      query += ' AND im.is_warming = true';
    } else if (filter === 'replies') {
      query += ' AND im.reply_to_id IS NOT NULL';
    }
    
    query += ' ORDER BY im.created_at DESC LIMIT $2';
    
    const result = await pool.query(query, [req.user.userId, limit]);
    
    // Get unread count
    const unread = await pool.query(
      'SELECT COUNT(*) as count FROM inbox_messages WHERE user_id = $1 AND is_read = false',
      [req.user.userId]
    );
    
    // Get reply stats
    const replyStats = await pool.query(`
      SELECT 
        COUNT(*) FILTER (WHERE reply_to_id IS NOT NULL) as total_replies,
        COUNT(*) FILTER (WHERE message_type = 'auto_reply') as auto_replies
      FROM inbox_messages WHERE user_id = $1
    `, [req.user.userId]);
    
    res.json({
      messages: result.rows,
      unreadCount: parseInt(unread.rows[0].count),
      replyStats: replyStats.rows[0]
    });
  } catch (error) {
    console.error('Get inbox error:', error);
    res.status(500).json({ error: 'Failed to get inbox' });
  }
});

// Get threads (grouped view)
app.get('/api/inbox/threads', authenticateToken, async (req, res) => {
  try {
    const { limit = 30 } = req.query;
    
    const result = await pool.query(`
      SELECT 
        t.*,
        (SELECT COUNT(*) FROM inbox_messages WHERE thread_id = t.thread_id AND is_read = false AND user_id = $1) as unread_count
      FROM threads t
      WHERE t.user_id = $1
      ORDER BY t.last_message_at DESC
      LIMIT $2
    `, [req.user.userId, limit]);
    
    res.json({ threads: result.rows });
  } catch (error) {
    console.error('Get threads error:', error);
    res.status(500).json({ error: 'Failed to get threads' });
  }
});

// Get messages in a thread
app.get('/api/inbox/threads/:threadId', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM inbox_messages 
      WHERE thread_id = $1 AND user_id = $2
      ORDER BY created_at ASC
    `, [req.params.threadId, req.user.userId]);
    
    // Mark all as read
    await pool.query(
      'UPDATE inbox_messages SET is_read = true WHERE thread_id = $1 AND user_id = $2',
      [req.params.threadId, req.user.userId]
    );
    
    res.json({ messages: result.rows });
  } catch (error) {
    console.error('Get thread error:', error);
    res.status(500).json({ error: 'Failed to get thread' });
  }
});

app.put('/api/inbox/:id/read', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      'UPDATE inbox_messages SET is_read = true WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.userId]
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Mark read error:', error);
    res.status(500).json({ error: 'Failed to mark as read' });
  }
});

app.post('/api/inbox/mark-all-read', authenticateToken, async (req, res) => {
  try {
    await pool.query('UPDATE inbox_messages SET is_read = true WHERE user_id = $1', [req.user.userId]);
    res.json({ success: true });
  } catch (error) {
    console.error('Mark all read error:', error);
    res.status(500).json({ error: 'Failed to mark all as read' });
  }
});

// ============================================
// CAMPAIGN ROUTES
// ============================================

app.get('/api/campaigns', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM campaigns WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.userId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Get campaigns error:', error);
    res.status(500).json({ error: 'Failed to get campaigns' });
  }
});

app.post('/api/campaigns', authenticateToken, async (req, res) => {
  try {
    const { name, subject, body, sendRate } = req.body;
    
    const result = await pool.query(
      'INSERT INTO campaigns (user_id, name, subject, body, send_rate) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.user.userId, name, subject, body, sendRate || 50]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Create campaign error:', error);
    res.status(500).json({ error: 'Failed to create campaign' });
  }
});

// ============================================
// WARMING ENGINE WITH THREADS & AUTO-REPLIES
// ============================================

const warmingTemplates = [
  { subject: 'Quick question', body: 'Hey! Just wanted to check in. How have things been going on your end?' },
  { subject: 'Following up', body: 'Hi there! Hope you\'re having a good week. Just following up on our last conversation.' },
  { subject: 'Interesting article', body: 'Found this article that reminded me of our discussion. Thought you might find it interesting!' },
  { subject: 'Weekend plans?', body: 'Hey! Any fun plans for the weekend? I\'m thinking of trying that new restaurant downtown.' },
  { subject: 'Meeting notes', body: 'Just wanted to send over some notes from our last meeting. Let me know if I missed anything!' },
  { subject: 'Great catching up', body: 'It was great chatting with you earlier! Looking forward to our next conversation.' },
  { subject: 'Thought of you', body: 'Saw something today that made me think of our last conversation. Hope you\'re doing well!' },
  { subject: 'Quick update', body: 'Just wanted to send a quick update on things. Everything is progressing nicely on our end.' },
  { subject: 'Coffee sometime?', body: 'Hey! Would love to grab coffee sometime and catch up properly. What does your schedule look like?' },
  { subject: 'Project update', body: 'Quick update on the project - things are moving along well. Let me know if you need any details.' }
];

const replyTemplates = [
  { body: 'Thanks for reaching out! Things are going well here. How about you?' },
  { body: 'Great to hear from you! Yes, let\'s definitely catch up soon.' },
  { body: 'Thanks for sharing! I\'ll take a look at it this weekend.' },
  { body: 'Sounds good! I\'m free next week if that works for you.' },
  { body: 'Appreciate the update! Keep me posted on any developments.' },
  { body: 'Good to hear! Let me know if you need anything from my end.' },
  { body: 'That sounds great! Looking forward to it.' },
  { body: 'Thanks for thinking of me! Hope all is well with you too.' }
];

function generateThreadId() {
  return `thread_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
}

async function createOrUpdateThread(userId, threadId, subject, participants, isWarming = true) {
  try {
    await pool.query(`
      INSERT INTO threads (user_id, thread_id, subject, participants, is_warming, last_message_at)
      VALUES ($1, $2, $3, $4, $5, NOW())
      ON CONFLICT (thread_id) 
      DO UPDATE SET message_count = threads.message_count + 1, last_message_at = NOW()
    `, [userId, threadId, subject, participants, isWarming]);
  } catch (error) {
    console.error('Create thread error:', error);
  }
}

async function sendWarmingEmail(fromEmail, toEmail, subject, body, userId, threadId = null, replyToId = null) {
  if (!resend) {
    console.log('⚠️ Resend not configured - skipping email');
    return null;
  }
  
  try {
    // Generate thread ID if new conversation
    const actualThreadId = threadId || generateThreadId();
    
    const result = await resend.emails.send({
      from: fromEmail,
      to: toEmail,
      subject: replyToId ? `Re: ${subject}` : subject,
      text: body,
      headers: {
        'X-Thread-ID': actualThreadId
      }
    });
    
    const messageId = crypto.randomUUID();
    const messageType = replyToId ? 'auto_reply' : 'sent';
    
    // Log to warming_emails
    await pool.query(`
      INSERT INTO warming_emails (user_id, from_email, to_email, subject, body, message_id, resend_id, status, thread_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7, 'sent', $8)
    `, [userId, fromEmail, toEmail, subject, body, messageId, result.data?.id, actualThreadId]);
    
    // Add to inbox
    const inboxResult = await pool.query(`
      INSERT INTO inbox_messages (user_id, message_type, from_email, to_email, subject, body, resend_id, is_warming, thread_id, reply_to_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7, true, $8, $9)
      RETURNING id
    `, [userId, messageType, fromEmail, toEmail, subject, body, result.data?.id, actualThreadId, replyToId]);
    
    // Create/update thread
    await createOrUpdateThread(userId, actualThreadId, subject, [fromEmail, toEmail], true);
    
    // If this was an original message (not a reply), update the original with reply info
    if (replyToId) {
      await pool.query(`
        UPDATE inbox_messages 
        SET reply_count = reply_count + 1, replied_at = NOW() 
        WHERE id = $1
      `, [replyToId]);
    }
    
    console.log(`🔥 ${replyToId ? 'Auto-reply' : 'Warming email'} sent: ${fromEmail} → ${toEmail} (${subject})`);
    
    return { 
      resendId: result.data?.id, 
      messageId: inboxResult.rows[0].id,
      threadId: actualThreadId 
    };
  } catch (error) {
    console.error('Failed to send warming email:', error.message);
    return null;
  }
}

async function scheduleAutoReply(originalMessage, userId, accounts) {
  // Random delay between 5-30 minutes for auto-reply
  const delayMinutes = Math.floor(Math.random() * 25) + 5;
  const delayMs = delayMinutes * 60 * 1000;
  
  console.log(`⏰ Auto-reply scheduled in ${delayMinutes} minutes for thread ${originalMessage.threadId}`);
  
  setTimeout(async () => {
    try {
      // Pick a reply template
      const replyTemplate = replyTemplates[Math.floor(Math.random() * replyTemplates.length)];
      
      // Send reply (swap from/to)
      await sendWarmingEmail(
        originalMessage.to,
        originalMessage.from,
        originalMessage.subject,
        replyTemplate.body,
        userId,
        originalMessage.threadId,
        originalMessage.messageId
      );
    } catch (error) {
      console.error('Auto-reply failed:', error);
    }
  }, delayMs);
}

async function runWarmingCycle() {
  try {
    // Get all active warming configs
    const activeUsers = await pool.query(`
      SELECT ws.*, u.email as user_email
      FROM warming_status ws
      JOIN users u ON ws.user_id = u.id
      WHERE ws.is_active = true
    `);
    
    for (const config of activeUsers.rows) {
      // Get verified email accounts for this user
      const accounts = await pool.query(`
        SELECT ea.email_address, d.domain_name
        FROM email_accounts ea
        JOIN domains d ON ea.domain_id = d.id
        WHERE ea.user_id = $1 
        AND ea.is_active = true 
        AND d.resend_verified = true
      `, [config.user_id]);
      
      if (accounts.rows.length < 2) {
        console.log(`⚠️ User ${config.user_id} needs at least 2 verified email accounts for warming`);
        continue;
      }
      
      // Calculate emails to send this cycle (run every 30 min = 48 cycles/day)
      const emailsThisCycle = Math.ceil(config.emails_per_day / 48);
      
      for (let i = 0; i < emailsThisCycle; i++) {
        // Pick random sender and recipient (different accounts)
        const senderIdx = Math.floor(Math.random() * accounts.rows.length);
        let recipientIdx = Math.floor(Math.random() * accounts.rows.length);
        while (recipientIdx === senderIdx && accounts.rows.length > 1) {
          recipientIdx = Math.floor(Math.random() * accounts.rows.length);
        }
        
        const sender = accounts.rows[senderIdx];
        const recipient = accounts.rows[recipientIdx];
        
        // Pick random template
        const template = warmingTemplates[Math.floor(Math.random() * warmingTemplates.length)];
        
        const result = await sendWarmingEmail(
          sender.email_address,
          recipient.email_address,
          template.subject,
          template.body,
          config.user_id
        );
        
        // Schedule auto-reply (70% chance)
        if (result && Math.random() < 0.7) {
          scheduleAutoReply({
            from: sender.email_address,
            to: recipient.email_address,
            subject: template.subject,
            threadId: result.threadId,
            messageId: result.messageId
          }, config.user_id, accounts.rows);
        }
        
        // Small delay between emails
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
      
      // Update last run time
      await pool.query('UPDATE warming_status SET last_run = NOW() WHERE user_id = $1', [config.user_id]);
    }
  } catch (error) {
    console.error('Warming cycle error:', error);
  }
}

// Run warming every 30 minutes
setInterval(runWarmingCycle, 30 * 60 * 1000);

// Run initial warming cycle after 1 minute
setTimeout(runWarmingCycle, 60 * 1000);

// ============================================
// HEALTH CHECK
// ============================================

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============================================
// START SERVER
// ============================================

async function startServer() {
  try {
    await initializeDatabase();
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📧 Resend configured: ${!!resend}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();
