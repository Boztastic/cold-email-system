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
