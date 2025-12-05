// =============================================================================
// AI WARMING ENGINE
// Hybrid approach: Smart templates + optional Claude AI for variety
// =============================================================================

const fetch = require('node-fetch');

// =============================================================================
// SMART EMAIL TEMPLATES (Randomized)
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
    subject: "Re: Our conversation",
    body: "Hi again,\n\nI was reflecting on our previous exchange and wanted to add a few more thoughts.\n\nHope all is well on your end!\n\nBest,\n{{sender_name}}"
  },
  {
    subject: "Weekend plans?",
    body: "Hey,\n\nHope your week is going well! Any fun plans for the weekend?\n\nI'm thinking of finally tackling that project I mentioned.\n\nTalk soon,\n{{sender_name}}"
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
  "time management", "automation tools", "communication platforms", "data analysis"
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
// AI RESPONSE GENERATOR (Claude API)
// =============================================================================

async function generateAIResponse(incomingEmail, context) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  
  if (!apiKey) {
    console.log('No Anthropic API key - using template response');
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
        messages: [
          {
            role: 'user',
            content: `You are writing a friendly, casual email reply for email warming purposes. Keep it natural, brief (3-5 sentences), and conversational. Don't be overly formal or salesy.

The incoming email was:
Subject: ${incomingEmail.subject}
Body: ${incomingEmail.body}

Write a natural reply from "${context.sender_name}". Just the email body, no subject line. Sign off with the sender's name.`
          }
        ]
      })
    });

    if (!response.ok) {
      console.error('Claude API error:', response.status);
      return null;
    }

    const data = await response.json();
    return data.content[0]?.text || null;
  } catch (error) {
    console.error('AI generation error:', error.message);
    return null;
  }
}

async function generateAIStarter(context) {
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
        max_tokens: 400,
        messages: [
          {
            role: 'user',
            content: `Write a short, friendly, casual email to start a conversation for email warming purposes. 

Topic: ${randomItem(TOPICS)}

The email should:
- Be 3-5 sentences
- Sound natural and human
- Ask a question to encourage a reply
- Not be salesy or promotional

Respond in JSON format: {"subject": "...", "body": "..."}

Sign off as "${context.sender_name}".`
          }
        ]
      })
    });

    if (!response.ok) {
      return null;
    }

    const data = await response.json();
    const text = data.content[0]?.text || '';
    
    // Parse JSON from response
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }
    return null;
  } catch (error) {
    console.error('AI starter generation error:', error.message);
    return null;
  }
}

// =============================================================================
// WARMING EMAIL GENERATOR
// =============================================================================

async function generateWarmingEmail(type, context, incomingEmail = null) {
  const useAI = process.env.ANTHROPIC_API_KEY && Math.random() < (context.aiFrequency || 0.3);
  
  if (type === 'starter') {
    // Generate conversation starter
    if (useAI) {
      const aiEmail = await generateAIStarter(context);
      if (aiEmail) {
        console.log('🤖 Using AI-generated starter');
        return { ...aiEmail, isAI: true };
      }
    }
    
    // Fallback to template
    const template = randomItem(CONVERSATION_STARTERS);
    return {
      subject: personalizeTemplate(template.subject, context),
      body: personalizeTemplate(template.body, context),
      isAI: false
    };
  } else if (type === 'reply') {
    // Generate reply to incoming email
    if (useAI && incomingEmail) {
      const aiReply = await generateAIResponse(incomingEmail, context);
      if (aiReply) {
        console.log('🤖 Using AI-generated reply');
        return {
          subject: `Re: ${incomingEmail.subject}`,
          body: aiReply,
          isAI: true
        };
      }
    }
    
    // Fallback to template
    const template = randomItem(REPLY_TEMPLATES);
    return {
      subject: incomingEmail ? `Re: ${incomingEmail.subject}` : 'Re: Our conversation',
      body: personalizeTemplate(template.body, { ...context, topic: randomItem(TOPICS) }),
      isAI: false
    };
  }
}

// =============================================================================
// WARMING SCHEDULER
// =============================================================================

class WarmingScheduler {
  constructor(db, emailSender) {
    this.db = db;
    this.emailSender = emailSender;
    this.activeJobs = new Map();
    this.conversations = new Map(); // Track ongoing conversations
  }

  async startWarming(userId, config) {
    const {
      emailsPerDay = 10,
      aiFrequency = 0.3, // 30% AI, 70% templates
      replyProbability = 0.8, // 80% chance to reply
      minDelayMinutes = 30,
      maxDelayMinutes = 180
    } = config;

    // Get user's warming accounts
    const accounts = await this.db.getWarmingAccountsForUser(userId);
    
    if (accounts.length < 2) {
      throw new Error('Need at least 2 warming accounts to start warming');
    }

    // Store config
    await this.db.query(`
      INSERT INTO warming_config (user_id, emails_per_day, ai_frequency, reply_probability, min_delay, max_delay, status)
      VALUES ($1, $2, $3, $4, $5, $6, 'active')
      ON CONFLICT (user_id) DO UPDATE SET 
        emails_per_day = $2, ai_frequency = $3, reply_probability = $4, 
        min_delay = $5, max_delay = $6, status = 'active', updated_at = NOW()
    `, [userId, emailsPerDay, aiFrequency, replyProbability, minDelayMinutes, maxDelayMinutes]);

    // Calculate interval between emails
    const intervalMs = (24 * 60 * 60 * 1000) / emailsPerDay;
    
    // Add randomization (+/- 30%)
    const getRandomInterval = () => {
      const variance = intervalMs * 0.3;
      return intervalMs + (Math.random() * variance * 2 - variance);
    };

    // Start the warming job
    const job = setInterval(async () => {
      try {
        await this.sendWarmingEmail(userId, accounts, { aiFrequency, replyProbability });
      } catch (error) {
        console.error('Warming job error:', error);
      }
    }, getRandomInterval());

    this.activeJobs.set(userId, job);
    
    // Send first email immediately
    setTimeout(() => {
      this.sendWarmingEmail(userId, accounts, { aiFrequency, replyProbability });
    }, randomDelay(1, 5));

    console.log(`🔥 Warming started for user ${userId}: ${emailsPerDay} emails/day`);
    return { status: 'started', emailsPerDay };
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

  async sendWarmingEmail(userId, accounts, config) {
    // Pick random sender and recipient (different accounts)
    const shuffled = [...accounts].sort(() => Math.random() - 0.5);
    const sender = shuffled[0];
    const recipient = shuffled[1];

    // Get sender name from email
    const senderName = sender.email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    const recipientName = recipient.email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase());

    const context = {
      sender_name: senderName,
      recipient_name: recipientName,
      aiFrequency: config.aiFrequency
    };

    // Check if this is a reply to an existing conversation
    const conversationKey = `${sender.email}-${recipient.email}`;
    const existingConversation = this.conversations.get(conversationKey);
    
    let email;
    if (existingConversation && Math.random() < config.replyProbability) {
      // Generate reply
      email = await generateWarmingEmail('reply', context, existingConversation.lastEmail);
      existingConversation.count++;
      existingConversation.lastEmail = email;
    } else {
      // Start new conversation
      email = await generateWarmingEmail('starter', context);
      this.conversations.set(conversationKey, { count: 1, lastEmail: email });
    }

    // Send the email
    try {
      await this.emailSender.sendWarmingEmail(sender, recipient.email, email.subject, email.body);
      
      // Log the warming email
      await this.db.query(`
        INSERT INTO warming_emails (user_id, sender_account_id, recipient_email, subject, is_ai_generated, created_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
      `, [userId, sender.id, recipient.email, email.subject, email.isAI]);

      // Update stats
      await this.db.query(`
        UPDATE warming_config 
        SET emails_sent_total = emails_sent_total + 1, 
            ai_emails_sent = ai_emails_sent + CASE WHEN $2 THEN 1 ELSE 0 END,
            last_email_at = NOW()
        WHERE user_id = $1
      `, [userId, email.isAI]);

      console.log(`🔥 Warming email sent: ${sender.email} → ${recipient.email} (${email.isAI ? 'AI' : 'Template'})`);
      
      // Schedule a reply from the recipient (if probability hits)
      if (Math.random() < config.replyProbability) {
        const replyDelay = randomDelay(15, 120); // 15 min to 2 hours
        setTimeout(async () => {
          try {
            await this.sendReplyEmail(userId, recipient, sender, email, config);
          } catch (error) {
            console.error('Reply send error:', error);
          }
        }, replyDelay);
      }
      
      return { success: true, from: sender.email, to: recipient.email };
    } catch (error) {
      console.error('Warming email send error:', error);
      throw error;
    }
  }

  async sendReplyEmail(userId, sender, recipient, originalEmail, config) {
    const senderName = sender.email.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    
    const context = {
      sender_name: senderName,
      aiFrequency: config.aiFrequency
    };

    const replyEmail = await generateWarmingEmail('reply', context, originalEmail);

    try {
      await this.emailSender.sendWarmingEmail(sender, recipient.email, replyEmail.subject, replyEmail.body);
      
      await this.db.query(`
        INSERT INTO warming_emails (user_id, sender_account_id, recipient_email, subject, is_reply, is_ai_generated, created_at)
        VALUES ($1, $2, $3, $4, true, $5, NOW())
      `, [userId, sender.id, recipient.email, replyEmail.subject, replyEmail.isAI]);

      await this.db.query(`
        UPDATE warming_config 
        SET replies_sent = replies_sent + 1, last_email_at = NOW()
        WHERE user_id = $1
      `, [userId]);

      console.log(`↩️ Reply sent: ${sender.email} → ${recipient.email}`);
    } catch (error) {
      console.error('Reply send error:', error);
    }
  }

  async getWarmingStats(userId) {
    const result = await this.db.query(`
      SELECT * FROM warming_config WHERE user_id = $1
    `, [userId]);
    
    if (result.rows.length === 0) {
      return { status: 'not_configured', emailsSent: 0, aiEmailsSent: 0, repliesSent: 0 };
    }

    const config = result.rows[0];
    
    // Get recent emails
    const recentEmails = await this.db.query(`
      SELECT we.*, wa.email as sender_email 
      FROM warming_emails we
      JOIN warming_accounts wa ON we.sender_account_id = wa.id
      WHERE we.user_id = $1 
      ORDER BY we.created_at DESC 
      LIMIT 20
    `, [userId]);

    return {
      status: config.status,
      emailsPerDay: config.emails_per_day,
      aiFrequency: config.ai_frequency,
      emailsSentTotal: config.emails_sent_total || 0,
      aiEmailsSent: config.ai_emails_sent || 0,
      repliesSent: config.replies_sent || 0,
      lastEmailAt: config.last_email_at,
      recentEmails: recentEmails.rows
    };
  }

  // Restore active warming jobs on server restart
  async restoreActiveJobs(emailSender) {
    try {
      const result = await this.db.query(`
        SELECT user_id, emails_per_day, ai_frequency, reply_probability, min_delay, max_delay 
        FROM warming_config WHERE status = 'active'
      `);

      for (const config of result.rows) {
        console.log(`🔄 Restoring warming for user ${config.user_id}`);
        await this.startWarming(config.user_id, {
          emailsPerDay: config.emails_per_day,
          aiFrequency: config.ai_frequency,
          replyProbability: config.reply_probability,
          minDelayMinutes: config.min_delay,
          maxDelayMinutes: config.max_delay
        });
      }
    } catch (error) {
      console.error('Error restoring warming jobs:', error);
    }
  }
}

// =============================================================================
// EXPORTS
// =============================================================================

module.exports = {
  WarmingScheduler,
  generateWarmingEmail,
  generateAIResponse,
  generateAIStarter,
  CONVERSATION_STARTERS,
  REPLY_TEMPLATES,
  TOPICS,
  INSIGHTS
};
