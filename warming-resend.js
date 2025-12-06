// =============================================================================
// RESEND WARMING ENGINE
// Automated email warming using Resend API + Cloudflare DNS
// Includes secure inbound email handling via webhooks
// =============================================================================

const fetch = require('node-fetch');
const crypto = require('crypto');

// =============================================================================
// WEBHOOK SIGNATURE VERIFICATION
// =============================================================================

function verifyWebhookSignature(payload, signature, secret) {
  if (!signature || !secret) {
    return false;
  }

  try {
    // Resend uses Svix for webhooks - signature format: v1,timestamp,signature
    const parts = signature.split(',');
    if (parts.length < 3) return false;
    
    const timestamp = parts.find(p => p.startsWith('t='))?.split('=')[1];
    const sig = parts.find(p => p.startsWith('v1='))?.split('=')[1];
    
    if (!timestamp || !sig) return false;

    // Check timestamp is within 5 minutes
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - parseInt(timestamp)) > 300) {
      console.warn('Webhook timestamp too old');
      return false;
    }

    // Verify signature
    const signedPayload = `${timestamp}.${payload}`;
    const expectedSig = crypto
      .createHmac('sha256', secret)
      .update(signedPayload)
      .digest('hex');

    return crypto.timingSafeEqual(
      Buffer.from(sig),
      Buffer.from(expectedSig)
    );
  } catch (error) {
    console.error('Webhook verification error:', error);
    return false;
  }
}

// Simple signature for non-Svix webhooks (fallback)
function verifySimpleSignature(payload, signature, secret) {
  if (!signature || !secret) return false;
  
  const expected = crypto
    .createHmac('sha256', secret)
    .update(typeof payload === 'string' ? payload : JSON.stringify(payload))
    .digest('hex');
  
  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected)
    );
  } catch {
    return signature === expected;
  }
}

// =============================================================================
// RESEND API CLIENT
// =============================================================================

class ResendClient {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.baseUrl = 'https://api.resend.com';
  }

  async request(endpoint, options = {}) {
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json',
        ...options.headers
      }
    });

    const data = await response.json();
    
    if (!response.ok) {
      throw new Error(data.message || `Resend API error: ${response.status}`);
    }
    
    return data;
  }

  // Add a domain to Resend
  async addDomain(domain) {
    return this.request('/domains', {
      method: 'POST',
      body: JSON.stringify({ name: domain })
    });
  }

  // Get domain details including DNS records needed
  async getDomain(domainId) {
    return this.request(`/domains/${domainId}`);
  }

  // List all domains
  async listDomains() {
    return this.request('/domains');
  }

  // Verify domain (trigger verification check)
  async verifyDomain(domainId) {
    return this.request(`/domains/${domainId}/verify`, {
      method: 'POST'
    });
  }

  // Delete domain
  async deleteDomain(domainId) {
    return this.request(`/domains/${domainId}`, {
      method: 'DELETE'
    });
  }

  // Send email
  async sendEmail({ from, to, subject, html, text, replyTo }) {
    return this.request('/emails', {
      method: 'POST',
      body: JSON.stringify({
        from,
        to: Array.isArray(to) ? to : [to],
        subject,
        html,
        text,
        reply_to: replyTo
      })
    });
  }
}

// =============================================================================
// SMART EMAIL TEMPLATES
// =============================================================================

const CONVERSATION_STARTERS = [
  {
    subject: "Quick question about {{topic}}",
    body: "Hi there,\n\nI've been thinking about {{topic}} lately and wanted to get your thoughts. Have you had any experience with this?\n\nWould love to hear your perspective.\n\nBest,\n{{sender_name}}"
  },
  {
    subject: "Interesting article on {{topic}}",
    body: "Hey,\n\nCame across something interesting about {{topic}} today and thought of you. Have you seen the latest developments in this space?\n\nLet me know what you think!\n\nCheers,\n{{sender_name}}"
  },
  {
    subject: "Catching up",
    body: "Hi,\n\nHope you're doing well! Just wanted to check in and see how things are going on your end.\n\nAnything exciting happening?\n\nTalk soon,\n{{sender_name}}"
  },
  {
    subject: "{{topic}} - your opinion?",
    body: "Hey there,\n\nI've been researching {{topic}} and I know you have some insight on this. What's your take on the current trends?\n\nAppreciate any thoughts you can share.\n\nThanks,\n{{sender_name}}"
  },
  {
    subject: "Following up on {{topic}}",
    body: "Hi,\n\nWanted to circle back on {{topic}}. I've done some more digging and found some interesting angles.\n\nWould be great to discuss when you have a moment.\n\nBest regards,\n{{sender_name}}"
  },
  {
    subject: "Quick thought",
    body: "Hey,\n\nHad a quick thought I wanted to run by you. Nothing urgent, just curious about your perspective on something.\n\nLet me know when you have a few minutes to chat.\n\nCheers,\n{{sender_name}}"
  },
  {
    subject: "Weekend plans?",
    body: "Hey,\n\nHope your week is going well! Any fun plans for the weekend?\n\nI'm thinking of finally tackling that project I mentioned.\n\nTalk soon,\n{{sender_name}}"
  },
  {
    subject: "Thought you'd find this interesting",
    body: "Hi,\n\nI came across something related to {{topic}} and immediately thought of you.\n\nWould love to hear your take on it when you have a moment.\n\nBest,\n{{sender_name}}"
  }
];

const REPLY_TEMPLATES = [
  {
    body: "Thanks for reaching out!\n\nThat's a great question about {{topic}}. I've actually been thinking about this too. From my experience, {{insight}}.\n\nWhat made you start looking into this?\n\nBest,\n{{sender_name}}"
  },
  {
    body: "Hey, great to hear from you!\n\nYes, I've definitely been following {{topic}}. It's fascinating how much things have evolved. {{insight}}\n\nLet me know if you want to dig deeper into any specific aspect.\n\nCheers,\n{{sender_name}}"
  },
  {
    body: "Hi there,\n\nThanks for your email! {{topic}} is definitely an interesting area. {{insight}}\n\nI'd love to hear more about what you're working on.\n\nBest regards,\n{{sender_name}}"
  },
  {
    body: "Good to hear from you!\n\nAbsolutely, {{topic}} has been on my radar as well. {{insight}}\n\nFeel free to share any resources you've found helpful.\n\nTalk soon,\n{{sender_name}}"
  },
  {
    body: "Hey!\n\nYes, things are going well here, thanks for asking! {{insight}}\n\nHow about you? Anything new and exciting?\n\nCheers,\n{{sender_name}}"
  },
  {
    body: "Thanks for the follow-up!\n\nI appreciate you thinking of me. {{insight}}\n\nLet's definitely continue this conversation.\n\nBest,\n{{sender_name}}"
  }
];

const TOPICS = [
  "productivity tools", "remote work", "industry trends", "new technologies",
  "project management", "team collaboration", "market developments", "best practices",
  "workflow optimization", "professional development", "networking strategies",
  "time management", "automation tools", "communication platforms", "data analysis",
  "growth strategies", "customer feedback", "process improvements", "team building"
];

const INSIGHTS = [
  "I've found that consistency is key when approaching this.",
  "The landscape has really changed over the past year.",
  "There are some exciting innovations happening in this space.",
  "I've seen mixed results, but overall the trend is positive.",
  "It's definitely worth exploring further.",
  "I've had some success with a few different approaches.",
  "The key is finding what works for your specific situation.",
  "I've been experimenting with some new methods recently.",
  "There's a lot of good information out there if you know where to look.",
  "I think we're just scratching the surface of what's possible."
];

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

function randomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomDelay(minMinutes, maxMinutes) {
  const min = minMinutes * 60 * 1000;
  const max = maxMinutes * 60 * 1000;
  return Math.floor(Math.random() * (max - min) + min);
}

function personalizeTemplate(template, context) {
  let result = template;
  result = result.replace(/\{\{topic\}\}/g, context.topic || randomItem(TOPICS));
  result = result.replace(/\{\{insight\}\}/g, context.insight || randomItem(INSIGHTS));
  result = result.replace(/\{\{sender_name\}\}/g, context.sender_name || 'Best');
  result = result.replace(/\{\{recipient_name\}\}/g, context.recipient_name || 'there');
  return result;
}

// =============================================================================
// AI RESPONSE GENERATOR (Optional - Claude API)
// =============================================================================

async function generateAIResponse(incomingEmail, context) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  
  if (!apiKey) {
    return null;
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 300,
        messages: [{
          role: 'user',
          content: `You are writing a friendly, casual email reply for email warming purposes. Keep it natural, brief (3-5 sentences), and conversational. Don't be overly formal or salesy.

The incoming email was:
Subject: ${incomingEmail.subject}
Body: ${incomingEmail.body}

Write a natural reply from "${context.sender_name}". Just the email body, no subject line. Sign off with the sender's name.`
        }]
      })
    });

    if (!response.ok) return null;
    const data = await response.json();
    return data.content[0]?.text || null;
  } catch (error) {
    console.error('AI generation error:', error.message);
    return null;
  }
}

async function generateAIStarter(context) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return null;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 400,
        messages: [{
          role: 'user',
          content: `Write a short, friendly, casual email to start a conversation for email warming purposes. 

Topic: ${randomItem(TOPICS)}

The email should be 3-5 sentences, sound natural and human, ask a question to encourage a reply, and not be salesy.

Respond in JSON format: {"subject": "...", "body": "..."}

Sign off as "${context.sender_name}".`
        }]
      })
    });

    if (!response.ok) return null;
    const data = await response.json();
    const text = data.content[0]?.text || '';
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) return JSON.parse(jsonMatch[0]);
    return null;
  } catch (error) {
    return null;
  }
}

// =============================================================================
// WARMING EMAIL GENERATOR
// =============================================================================

async function generateWarmingEmail(type, context, incomingEmail = null) {
  const useAI = process.env.ANTHROPIC_API_KEY && Math.random() < (context.aiFrequency || 0.3);
  
  if (type === 'starter') {
    if (useAI) {
      const aiEmail = await generateAIStarter(context);
      if (aiEmail) {
        console.log('🤖 Using AI-generated starter');
        return { ...aiEmail, isAI: true };
      }
    }
    
    const template = randomItem(CONVERSATION_STARTERS);
    return {
      subject: personalizeTemplate(template.subject, context),
      body: personalizeTemplate(template.body, context),
      isAI: false
    };
  } else if (type === 'reply') {
    if (useAI && incomingEmail) {
      const aiReply = await generateAIResponse(incomingEmail, context);
      if (aiReply) {
        console.log('🤖 Using AI-generated reply');
        return { subject: `Re: ${incomingEmail.subject}`, body: aiReply, isAI: true };
      }
    }
    
    const template = randomItem(REPLY_TEMPLATES);
    return {
      subject: incomingEmail ? `Re: ${incomingEmail.subject}` : 'Re: Our conversation',
      body: personalizeTemplate(template.body, { ...context, topic: randomItem(TOPICS) }),
      isAI: false
    };
  }
}

// =============================================================================
// RESEND WARMING SCHEDULER
// =============================================================================

class ResendWarmingScheduler {
  constructor(db) {
    this.db = db;
    this.resend = null;
    this.activeJobs = new Map();
    this.conversations = new Map();
    
    if (process.env.RESEND_API_KEY) {
      this.resend = new ResendClient(process.env.RESEND_API_KEY);
      console.log('✅ Resend API connected');
    } else {
      console.warn('⚠️  RESEND_API_KEY not set - warming disabled');
    }
  }

  // Setup domain in Resend and configure DNS via Cloudflare
  async setupDomainForWarming(userId, domainId, cloudflareClient) {
    if (!this.resend) throw new Error('Resend API not configured');

    // Get domain from database
    const domainResult = await this.db.query(
      'SELECT * FROM domains WHERE id = $1 AND user_id = $2',
      [domainId, userId]
    );
    
    if (domainResult.rows.length === 0) {
      throw new Error('Domain not found');
    }
    
    const domain = domainResult.rows[0];
    const domainName = domain.domain_name;

    console.log(`🔧 Setting up warming for ${domainName}...`);

    // Step 1: Check if domain already exists in Resend, or add it
    let resendDomain;
    try {
      // First check if it already exists
      const existingDomains = await this.resend.listDomains();
      resendDomain = existingDomains.data?.find(d => d.name === domainName);
      
      if (resendDomain) {
        console.log(`✅ Found existing domain ${domainName} in Resend (id: ${resendDomain.id})`);
      } else {
        // Add new domain
        resendDomain = await this.resend.addDomain(domainName);
        console.log(`✅ Added ${domainName} to Resend`);
      }
    } catch (error) {
      console.error('Resend domain error:', error.message);
      throw error;
    }

    // Step 2: Get DNS records needed from Resend
    const domainDetails = await this.resend.getDomain(resendDomain.id);
    const records = domainDetails.records || [];

    // Step 3: Add DNS records via Cloudflare
    const zoneId = domain.zone_id;
    if (!zoneId) {
      throw new Error('Domain not connected to Cloudflare');
    }

    // Add Resend's sending records (SPF, DKIM, etc.)
    for (const record of records) {
      try {
        await cloudflareClient.createDNSRecord(zoneId, {
          type: record.type,
          name: record.name,
          content: record.value,
          ttl: 3600,
          priority: record.priority || undefined
        });
        console.log(`✅ Added ${record.type} record: ${record.name}`);
      } catch (error) {
        // Record might already exist
        if (!error.message.includes('already exists') && !error.message.includes('already been taken')) {
          console.warn(`⚠️  Failed to add ${record.type} record: ${error.message}`);
        }
      }
    }

    // Step 4: Enable Cloudflare Email Routing for receiving emails
    // This automatically adds the correct MX records
    let emailRoutingStatus = { enabled: false, destinationVerified: false };
    try {
      // Get user's email for forwarding
      const userResult = await this.db.query('SELECT email FROM users WHERE id = $1', [userId]);
      const userEmail = userResult.rows[0]?.email;
      
      if (userEmail) {
        // Enable Email Routing (adds MX records automatically)
        try {
          await cloudflareClient.enableEmailRouting(zoneId);
          console.log(`✅ Enabled Cloudflare Email Routing for ${domainName}`);
          emailRoutingStatus.enabled = true;
        } catch (error) {
          // Might already be enabled
          if (error.message.includes('already enabled') || error.message.includes('already exists')) {
            emailRoutingStatus.enabled = true;
          } else {
            console.warn(`⚠️  Email routing enable warning: ${error.message}`);
          }
        }
        
        // Set up catch-all forwarding
        try {
          const forwardingResult = await cloudflareClient.createCatchAllForwarding(zoneId, userEmail);
          emailRoutingStatus.destinationVerified = forwardingResult.destinationVerified;
          
          if (!forwardingResult.destinationVerified) {
            console.log(`📧 Verification email sent to ${userEmail} - user must click to activate`);
          } else {
            console.log(`✅ Catch-all forwarding active: *@${domainName} → ${userEmail}`);
          }
        } catch (error) {
          console.warn(`⚠️  Catch-all setup warning: ${error.message}`);
        }

        // Update domain record
        await this.db.query(`
          UPDATE domains SET 
            email_routing_enabled = $1,
            forward_to = $2,
            destination_verified = $3,
            updated_at = NOW()
          WHERE id = $4
        `, [emailRoutingStatus.enabled, userEmail, emailRoutingStatus.destinationVerified, domainId]);
      }
    } catch (error) {
      console.warn(`⚠️  Email routing setup warning: ${error.message}`);
    }

    // Step 5: Trigger verification
    await this.resend.verifyDomain(resendDomain.id);

    // Step 6: Update database
    await this.db.query(`
      UPDATE domains SET 
        warming_enabled = true,
        resend_domain_id = $1,
        warming_status = 'pending_verification',
        updated_at = NOW()
      WHERE id = $2
    `, [resendDomain.id, domainId]);

    // Step 7: Create warming email addresses
    const warmingAddresses = [
      `team@${domainName}`,
      `hello@${domainName}`,
      `contact@${domainName}`,
      `info@${domainName}`
    ];

    // Store warming addresses
    await this.db.query(`
      INSERT INTO warming_addresses (user_id, domain_id, email_address, display_name, created_at)
      VALUES 
        ($1, $2, $3, 'Team', NOW()),
        ($1, $2, $4, 'Hello', NOW()),
        ($1, $2, $5, 'Contact', NOW()),
        ($1, $2, $6, 'Info', NOW())
      ON CONFLICT (email_address) DO NOTHING
    `, [userId, domainId, ...warmingAddresses]);

    console.log(`✅ Warming setup complete for ${domainName}`);

    return {
      domain: domainName,
      resendDomainId: resendDomain.id,
      status: 'pending_verification',
      addresses: warmingAddresses,
      dnsRecords: records.length
    };
  }

  // Check domain verification status
  async checkDomainVerification(domainId) {
    const result = await this.db.query(
      'SELECT resend_domain_id, domain_name FROM domains WHERE id = $1',
      [domainId]
    );
    
    if (result.rows.length === 0 || !result.rows[0].resend_domain_id) {
      return { verified: false, status: 'not_configured' };
    }

    const domainDetails = await this.resend.getDomain(result.rows[0].resend_domain_id);
    const verified = domainDetails.status === 'verified';

    if (verified) {
      await this.db.query(`
        UPDATE domains SET warming_status = 'verified', updated_at = NOW()
        WHERE id = $1
      `, [domainId]);
    }

    return {
      verified,
      status: domainDetails.status,
      domain: result.rows[0].domain_name
    };
  }

  // Start warming for a user's domains
  async startWarming(userId, config) {
    const {
      emailsPerDay = 10,
      aiFrequency = 0.3,
      replyProbability = 0.8
    } = config;

    // Get user's warming-enabled domains
    const domainsResult = await this.db.query(`
      SELECT d.*, array_agg(wa.email_address) as addresses
      FROM domains d
      LEFT JOIN warming_addresses wa ON wa.domain_id = d.id
      WHERE d.user_id = $1 AND d.warming_enabled = true AND d.warming_status = 'verified'
      GROUP BY d.id
    `, [userId]);

    if (domainsResult.rows.length === 0) {
      throw new Error('No verified warming domains. Enable warming on a domain first.');
    }

    // Collect all warming addresses
    const allAddresses = [];
    for (const domain of domainsResult.rows) {
      if (domain.addresses && domain.addresses[0]) {
        for (const addr of domain.addresses) {
          if (addr) allAddresses.push({ email: addr, domain: domain.domain_name });
        }
      }
    }

    if (allAddresses.length < 2) {
      throw new Error('Need at least 2 warming addresses');
    }

    // Store config
    await this.db.query(`
      INSERT INTO warming_config (user_id, emails_per_day, ai_frequency, reply_probability, status)
      VALUES ($1, $2, $3, $4, 'active')
      ON CONFLICT (user_id) DO UPDATE SET 
        emails_per_day = $2, ai_frequency = $3, reply_probability = $4, 
        status = 'active', updated_at = NOW()
    `, [userId, emailsPerDay, aiFrequency, replyProbability]);

    // Calculate interval
    const intervalMs = (24 * 60 * 60 * 1000) / emailsPerDay;
    const getRandomInterval = () => intervalMs + (Math.random() * intervalMs * 0.6 - intervalMs * 0.3);

    // Stop existing job if any
    if (this.activeJobs.has(userId)) {
      clearInterval(this.activeJobs.get(userId));
    }

    // Start warming job
    const job = setInterval(async () => {
      try {
        await this.sendWarmingEmail(userId, allAddresses, { aiFrequency, replyProbability });
      } catch (error) {
        console.error('Warming job error:', error.message);
      }
    }, getRandomInterval());

    this.activeJobs.set(userId, job);

    // Send first email soon
    setTimeout(() => {
      this.sendWarmingEmail(userId, allAddresses, { aiFrequency, replyProbability })
        .catch(err => console.error('First warming email error:', err.message));
    }, randomDelay(1, 3));

    console.log(`🔥 Warming started for user ${userId}: ${emailsPerDay} emails/day, ${allAddresses.length} addresses`);

    return { 
      status: 'started', 
      emailsPerDay, 
      addresses: allAddresses.map(a => a.email)
    };
  }

  async stopWarming(userId) {
    const job = this.activeJobs.get(userId);
    if (job) {
      clearInterval(job);
      this.activeJobs.delete(userId);
    }

    await this.db.query(`
      UPDATE warming_config SET status = 'paused', updated_at = NOW() WHERE user_id = $1
    `, [userId]);

    console.log(`⏸️ Warming stopped for user ${userId}`);
    return { status: 'stopped' };
  }

  async sendWarmingEmail(userId, addresses, config) {
    if (!this.resend) throw new Error('Resend not configured');

    // Pick random sender and recipient
    const shuffled = [...addresses].sort(() => Math.random() - 0.5);
    const sender = shuffled[0];
    const recipient = shuffled[1];

    const senderName = sender.email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    const recipientName = recipient.email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase());

    const context = {
      sender_name: senderName,
      recipient_name: recipientName,
      aiFrequency: config.aiFrequency
    };

    // Check for existing conversation
    const conversationKey = `${sender.email}-${recipient.email}`;
    const existingConversation = this.conversations.get(conversationKey);

    let email;
    if (existingConversation && Math.random() < config.replyProbability) {
      email = await generateWarmingEmail('reply', context, existingConversation.lastEmail);
      existingConversation.count++;
      existingConversation.lastEmail = email;
    } else {
      email = await generateWarmingEmail('starter', context);
      this.conversations.set(conversationKey, { count: 1, lastEmail: email });
    }

    // Send via Resend
    try {
      await this.resend.sendEmail({
        from: `${senderName} <${sender.email}>`,
        to: recipient.email,
        subject: email.subject,
        text: email.body,
        html: email.body.replace(/\n/g, '<br>')
      });

      // Log the email
      await this.db.query(`
        INSERT INTO warming_emails (user_id, sender_email, recipient_email, subject, is_ai_generated, created_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
      `, [userId, sender.email, recipient.email, email.subject, email.isAI]);

      // Update stats
      await this.db.query(`
        UPDATE warming_config 
        SET emails_sent_total = COALESCE(emails_sent_total, 0) + 1,
            ai_emails_sent = COALESCE(ai_emails_sent, 0) + CASE WHEN $2 THEN 1 ELSE 0 END,
            last_email_at = NOW()
        WHERE user_id = $1
      `, [userId, email.isAI]);

      console.log(`🔥 Warming email sent: ${sender.email} → ${recipient.email} (${email.isAI ? 'AI' : 'Template'})`);

      // Schedule reply
      if (Math.random() < config.replyProbability) {
        setTimeout(async () => {
          try {
            await this.sendReplyEmail(userId, recipient, sender, email, config);
          } catch (err) {
            console.error('Reply error:', err.message);
          }
        }, randomDelay(15, 90));
      }

      return { success: true, from: sender.email, to: recipient.email };
    } catch (error) {
      console.error('Warming email send error:', error.message);
      throw error;
    }
  }

  async sendReplyEmail(userId, sender, recipient, originalEmail, config) {
    const senderName = sender.email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    const context = { sender_name: senderName, aiFrequency: config.aiFrequency };

    const replyEmail = await generateWarmingEmail('reply', context, originalEmail);

    await this.resend.sendEmail({
      from: `${senderName} <${sender.email}>`,
      to: recipient.email,
      subject: replyEmail.subject,
      text: replyEmail.body,
      html: replyEmail.body.replace(/\n/g, '<br>')
    });

    await this.db.query(`
      INSERT INTO warming_emails (user_id, sender_email, recipient_email, subject, is_reply, is_ai_generated, created_at)
      VALUES ($1, $2, $3, $4, true, $5, NOW())
    `, [userId, sender.email, recipient.email, replyEmail.subject, replyEmail.isAI]);

    await this.db.query(`
      UPDATE warming_config SET replies_sent = COALESCE(replies_sent, 0) + 1, last_email_at = NOW()
      WHERE user_id = $1
    `, [userId]);

    console.log(`↩️ Reply sent: ${sender.email} → ${recipient.email}`);
  }

  async getWarmingStats(userId) {
    const configResult = await this.db.query(
      'SELECT * FROM warming_config WHERE user_id = $1',
      [userId]
    );

    if (configResult.rows.length === 0) {
      return { status: 'not_configured' };
    }

    const config = configResult.rows[0];

    // Get domains with warming
    const domainsResult = await this.db.query(`
      SELECT domain_name, warming_status, warming_enabled 
      FROM domains WHERE user_id = $1 AND warming_enabled = true
    `, [userId]);

    // Get recent emails
    const emailsResult = await this.db.query(`
      SELECT * FROM warming_emails 
      WHERE user_id = $1 
      ORDER BY created_at DESC 
      LIMIT 20
    `, [userId]);

    // Get first email date for progress calculation
    const firstEmailResult = await this.db.query(`
      SELECT MIN(created_at) as started_at FROM warming_emails WHERE user_id = $1
    `, [userId]);

    return {
      status: config.status,
      emailsPerDay: config.emails_per_day,
      aiFrequency: parseFloat(config.ai_frequency),
      replyProbability: parseFloat(config.reply_probability),
      emailsSentTotal: config.emails_sent_total || 0,
      aiEmailsSent: config.ai_emails_sent || 0,
      repliesSent: config.replies_sent || 0,
      lastEmailAt: config.last_email_at,
      startedAt: firstEmailResult.rows[0]?.started_at || config.created_at,
      domains: domainsResult.rows,
      recentEmails: emailsResult.rows
    };
  }

  async restoreActiveJobs() {
    try {
      const result = await this.db.query(`
        SELECT user_id, emails_per_day, ai_frequency, reply_probability 
        FROM warming_config WHERE status = 'active'
      `);

      for (const config of result.rows) {
        console.log(`🔄 Restoring warming for user ${config.user_id}`);
        try {
          await this.startWarming(config.user_id, {
            emailsPerDay: config.emails_per_day,
            aiFrequency: parseFloat(config.ai_frequency),
            replyProbability: parseFloat(config.reply_probability)
          });
        } catch (error) {
          console.error(`Failed to restore warming for ${config.user_id}:`, error.message);
        }
      }
    } catch (error) {
      console.error('Error restoring warming jobs:', error);
    }
  }

  // =============================================================================
  // INBOUND EMAIL HANDLING
  // =============================================================================

  async processInboundEmail(inboundData) {
    console.log('📥 Processing inbound email...');
    
    const { from, to, subject, text, html } = inboundData;
    
    // Extract email addresses
    const fromEmail = this.extractEmail(from);
    const toEmail = this.extractEmail(Array.isArray(to) ? to[0] : to);
    
    if (!fromEmail || !toEmail) {
      console.warn('Invalid from/to addresses:', { from, to });
      return { processed: false, reason: 'Invalid addresses' };
    }

    console.log(`📧 Inbound: ${fromEmail} → ${toEmail}`);
    console.log(`📝 Subject: ${subject}`);

    // Verify recipient is one of our warming addresses
    const recipientCheck = await this.db.query(
      'SELECT wa.*, d.user_id FROM warming_addresses wa JOIN domains d ON wa.domain_id = d.id WHERE wa.email_address = $1',
      [toEmail.toLowerCase()]
    );

    if (recipientCheck.rows.length === 0) {
      console.warn(`Recipient ${toEmail} not a warming address`);
      return { processed: false, reason: 'Not a warming address' };
    }

    const recipientAddress = recipientCheck.rows[0];
    const userId = recipientAddress.user_id;

    // Verify sender is also one of our warming addresses (for security)
    const senderCheck = await this.db.query(
      'SELECT wa.*, d.user_id FROM warming_addresses wa JOIN domains d ON wa.domain_id = d.id WHERE wa.email_address = $1 AND d.user_id = $2',
      [fromEmail.toLowerCase(), userId]
    );

    if (senderCheck.rows.length === 0) {
      console.warn(`Sender ${fromEmail} not a valid warming address for this user`);
      // Log as external email but don't auto-reply
      await this.logInboundEmail(userId, fromEmail, toEmail, subject, false);
      return { processed: true, replied: false, reason: 'External sender' };
    }

    // Log the inbound email
    await this.logInboundEmail(userId, fromEmail, toEmail, subject, true);

    // Check warming config for reply probability
    const configResult = await this.db.query(
      'SELECT * FROM warming_config WHERE user_id = $1',
      [userId]
    );

    if (configResult.rows.length === 0 || configResult.rows[0].status !== 'active') {
      console.log('Warming not active, skipping auto-reply');
      return { processed: true, replied: false, reason: 'Warming not active' };
    }

    const config = configResult.rows[0];
    const replyProbability = parseFloat(config.reply_probability) || 0.8;

    // Decide whether to reply based on probability
    if (Math.random() > replyProbability) {
      console.log(`Skipping reply (probability: ${replyProbability})`);
      return { processed: true, replied: false, reason: 'Random skip' };
    }

    // Generate and send reply
    try {
      // Delay reply by 1-5 minutes to seem natural
      const delayMinutes = Math.floor(Math.random() * 4) + 1;
      
      setTimeout(async () => {
        await this.sendAutoReply(userId, toEmail, fromEmail, subject, text || html, config);
      }, delayMinutes * 60 * 1000);

      console.log(`⏰ Auto-reply scheduled in ${delayMinutes} minutes`);
      return { processed: true, replied: true, delay: delayMinutes };
    } catch (error) {
      console.error('Error scheduling reply:', error);
      return { processed: true, replied: false, reason: error.message };
    }
  }

  extractEmail(str) {
    if (!str) return null;
    // Handle formats like "Name <email@domain.com>" or just "email@domain.com"
    const match = str.match(/<([^>]+)>/) || str.match(/([^\s<>]+@[^\s<>]+)/);
    return match ? match[1].toLowerCase() : null;
  }

  async logInboundEmail(userId, from, to, subject, isWarming) {
    try {
      await this.db.query(`
        INSERT INTO inbound_emails (user_id, from_email, to_email, subject, is_warming, created_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
      `, [userId, from, to, subject, isWarming]);
    } catch (error) {
      // Table might not exist yet, log but don't fail
      console.warn('Could not log inbound email:', error.message);
    }
  }

  async sendAutoReply(userId, from, to, originalSubject, originalContent, config) {
    console.log(`📤 Sending auto-reply: ${from} → ${to}`);

    try {
      // Get sender's display name
      const addressResult = await this.db.query(
        'SELECT display_name FROM warming_addresses WHERE email_address = $1',
        [from.toLowerCase()]
      );
      const senderName = addressResult.rows[0]?.display_name || from.split('@')[0];

      // Generate reply content
      const context = {
        senderName,
        senderEmail: from,
        topic: this.extractTopic(originalSubject),
        aiFrequency: parseFloat(config.ai_frequency) || 0.3
      };

      const replyContent = await generateWarmingEmail('reply', context, {
        subject: originalSubject,
        body: originalContent
      });

      // Send via Resend
      const result = await this.resend.sendEmail({
        from: `${senderName} <${from}>`,
        to: to,
        subject: replyContent.subject,
        text: replyContent.body,
        html: `<div style="font-family: Arial, sans-serif; line-height: 1.6;">${replyContent.body.replace(/\n/g, '<br>')}</div>`
      });

      // Log the reply
      await this.db.query(`
        INSERT INTO warming_emails (user_id, sender_email, recipient_email, subject, is_reply, is_ai_generated, created_at)
        VALUES ($1, $2, $3, $4, true, $5, NOW())
      `, [userId, from, to, replyContent.subject, replyContent.isAI]);

      // Update stats
      await this.db.query(`
        UPDATE warming_config SET 
          replies_sent = COALESCE(replies_sent, 0) + 1,
          emails_sent_total = COALESCE(emails_sent_total, 0) + 1,
          ai_emails_sent = ai_emails_sent + $1,
          last_email_at = NOW()
        WHERE user_id = $2
      `, [replyContent.isAI ? 1 : 0, userId]);

      console.log(`✅ Auto-reply sent successfully (ID: ${result.id})`);
      return result;
    } catch (error) {
      console.error('Auto-reply error:', error);
      throw error;
    }
  }

  extractTopic(subject) {
    // Remove Re:, Fwd:, etc. and extract key topic
    const cleaned = subject.replace(/^(Re:|Fwd:|Fw:)\s*/gi, '').trim();
    return cleaned || 'our conversation';
  }
}

// =============================================================================
// INBOUND EMAIL TABLE MIGRATION
// =============================================================================

const INBOUND_TABLE_SQL = `
  CREATE TABLE IF NOT EXISTS inbound_emails (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    from_email VARCHAR(255) NOT NULL,
    to_email VARCHAR(255) NOT NULL,
    subject VARCHAR(500),
    is_warming BOOLEAN DEFAULT false,
    processed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_inbound_emails_user ON inbound_emails(user_id);
  CREATE INDEX IF NOT EXISTS idx_inbound_emails_created ON inbound_emails(created_at);
`;

// =============================================================================
// EXPORTS
// =============================================================================

module.exports = {
  ResendClient,
  ResendWarmingScheduler,
  generateWarmingEmail,
  verifyWebhookSignature,
  verifySimpleSignature,
  INBOUND_TABLE_SQL,
  CONVERSATION_STARTERS,
  REPLY_TEMPLATES,
  TOPICS,
  INSIGHTS
};
