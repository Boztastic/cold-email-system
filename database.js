// ============================================================================
// DATABASE MODULE - COMPLETE VERSION WITH ALL FEATURES
// Includes: Users, Campaigns, Sequences, Templates, Tracking, Analytics
// ============================================================================

const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// ============================================================================
// DATABASE CONNECTION POOL
// ============================================================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

pool.on('error', (err) => {
  console.error('Unexpected error on idle database client', err);
});

// Test connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('❌ Database connection failed:', err.message);
  } else {
    console.log('✅ Database connected successfully at', res.rows[0].now);
  }
});

// ============================================================================
// MIGRATION - RUN ON STARTUP
// ============================================================================

async function runMigrations() {
  const client = await pool.connect();
  
  try {
    console.log('🔄 Running database migrations...');
    
    // Enable UUID extension
    await client.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');
    
    // ========================================
    // USERS TABLE
    // ========================================
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL DEFAULT 'user',
        active BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    `);
    
    // ========================================
    // INVITATIONS TABLE
    // ========================================
    await client.query(`
      CREATE TABLE IF NOT EXISTS invitations (
        token VARCHAR(255) PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL DEFAULT 'user',
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations(email);
    `);
    
    // ========================================
    // WARMING ACCOUNTS TABLE
    // ========================================
    await client.query(`
      CREATE TABLE IF NOT EXISTS warming_accounts (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email VARCHAR(255) UNIQUE NOT NULL,
        smtp_host VARCHAR(255) NOT NULL,
        smtp_port INTEGER NOT NULL,
        smtp_user VARCHAR(255) NOT NULL,
        smtp_pass TEXT NOT NULL,
        imap_host VARCHAR(255) NOT NULL,
        imap_port INTEGER NOT NULL,
        status VARCHAR(50) NOT NULL DEFAULT 'active',
        daily_limit INTEGER DEFAULT 50,
        emails_sent_today INTEGER DEFAULT 0,
        last_used_at TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_warming_accounts_status ON warming_accounts(status);
    `);

    // ========================================
    // CONTACTS TABLE
    // ========================================
    await client.query(`
      CREATE TABLE IF NOT EXISTS contacts (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email VARCHAR(255) UNIQUE NOT NULL,
        first_name VARCHAR(255),
        last_name VARCHAR(255),
        company VARCHAR(255),
        title VARCHAR(255),
        phone VARCHAR(50),
        tags TEXT[],
        custom_fields JSONB DEFAULT '{}',
        status VARCHAR(50) DEFAULT 'active',
        unsubscribed BOOLEAN DEFAULT false,
        unsubscribed_at TIMESTAMP WITH TIME ZONE,
        bounced BOOLEAN DEFAULT false,
        bounce_reason TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_contacts_email ON contacts(email);
      CREATE INDEX IF NOT EXISTS idx_contacts_status ON contacts(status);
      CREATE INDEX IF NOT EXISTS idx_contacts_unsubscribed ON contacts(unsubscribed);
    `);

    // ========================================
    // EMAIL TEMPLATES TABLE
    // ========================================
    await client.query(`
      CREATE TABLE IF NOT EXISTS email_templates (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        name VARCHAR(255) NOT NULL,
        subject VARCHAR(500) NOT NULL,
        body TEXT NOT NULL,
        category VARCHAR(100),
        is_default BOOLEAN DEFAULT false,
        created_by UUID REFERENCES users(id),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_templates_category ON email_templates(category);
    `);

    // ========================================
    // CAMPAIGNS TABLE (Enhanced)
    // ========================================
    await client.query(`
      CREATE TABLE IF NOT EXISTS campaigns (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        name VARCHAR(255) NOT NULL,
        subject VARCHAR(500) NOT NULL,
        body TEXT NOT NULL,
        from_name VARCHAR(255) NOT NULL,
        from_email VARCHAR(255) NOT NULL,
        reply_to VARCHAR(255),
        status VARCHAR(50) NOT NULL DEFAULT 'draft',
        type VARCHAR(50) DEFAULT 'single',
        scheduled_at TIMESTAMP WITH TIME ZONE,
        started_at TIMESTAMP WITH TIME ZONE,
        completed_at TIMESTAMP WITH TIME ZONE,
        total_recipients INTEGER DEFAULT 0,
        emails_sent INTEGER DEFAULT 0,
        emails_delivered INTEGER DEFAULT 0,
        emails_opened INTEGER DEFAULT 0,
        emails_clicked INTEGER DEFAULT 0,
        emails_replied INTEGER DEFAULT 0,
        emails_bounced INTEGER DEFAULT 0,
        emails_unsubscribed INTEGER DEFAULT 0,
        sending_rate INTEGER DEFAULT 30,
        created_by UUID REFERENCES users(id),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns(status);
      CREATE INDEX IF NOT EXISTS idx_campaigns_type ON campaigns(type);
    `);

    // ========================================
    // SEQUENCES TABLE (Follow-up Campaigns)
    // ========================================
    await client.query(`
      CREATE TABLE IF NOT EXISTS sequences (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        name VARCHAR(255) NOT NULL,
        description TEXT,
        status VARCHAR(50) DEFAULT 'draft',
        from_name VARCHAR(255) NOT NULL,
        from_email VARCHAR(255) NOT NULL,
        total_contacts INTEGER DEFAULT 0,
        active_contacts INTEGER DEFAULT 0,
        completed_contacts INTEGER DEFAULT 0,
        created_by UUID REFERENCES users(id),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_sequences_status ON sequences(status);
    `);

    // ========================================
    // SEQUENCE STEPS TABLE
    // ========================================
    await client.query(`
      CREATE TABLE IF NOT EXISTS sequence_steps (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        sequence_id UUID NOT NULL REFERENCES sequences(id) ON DELETE CASCADE,
        step_number INTEGER NOT NULL,
        subject VARCHAR(500) NOT NULL,
        body TEXT NOT NULL,
        delay_days INTEGER DEFAULT 1,
        delay_hours INTEGER DEFAULT 0,
        send_if_no_reply BOOLEAN DEFAULT true,
        send_if_no_open BOOLEAN DEFAULT false,
        emails_sent INTEGER DEFAULT 0,
        emails_opened INTEGER DEFAULT 0,
        emails_clicked INTEGER DEFAULT 0,
        emails_replied INTEGER DEFAULT 0,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(sequence_id, step_number)
      );
      CREATE INDEX IF NOT EXISTS idx_sequence_steps_sequence ON sequence_steps(sequence_id);
    `);

    // ========================================
    // SEQUENCE CONTACTS TABLE
    // ========================================
    await client.query(`
      CREATE TABLE IF NOT EXISTS sequence_contacts (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        sequence_id UUID NOT NULL REFERENCES sequences(id) ON DELETE CASCADE,
        contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
        current_step INTEGER DEFAULT 1,
        status VARCHAR(50) DEFAULT 'active',
        last_email_at TIMESTAMP WITH TIME ZONE,
        next_email_at TIMESTAMP WITH TIME ZONE,
        completed_at TIMESTAMP WITH TIME ZONE,
        replied BOOLEAN DEFAULT false,
        opened BOOLEAN DEFAULT false,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(sequence_id, contact_id)
      );
      CREATE INDEX IF NOT EXISTS idx_seq_contacts_sequence ON sequence_contacts(sequence_id);
      CREATE INDEX IF NOT EXISTS idx_seq_contacts_status ON sequence_contacts(status);
      CREATE INDEX IF NOT EXISTS idx_seq_contacts_next_email ON sequence_contacts(next_email_at);
    `);

    // ========================================
    // EMAIL QUEUE TABLE
    // ========================================
    await client.query(`
      CREATE TABLE IF NOT EXISTS email_queue (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        campaign_id UUID REFERENCES campaigns(id) ON DELETE CASCADE,
        sequence_id UUID REFERENCES sequences(id) ON DELETE CASCADE,
        sequence_step_id UUID REFERENCES sequence_steps(id) ON DELETE CASCADE,
        contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
        warming_account_id UUID REFERENCES warming_accounts(id),
        to_email VARCHAR(255) NOT NULL,
        to_name VARCHAR(255),
        from_email VARCHAR(255) NOT NULL,
        from_name VARCHAR(255) NOT NULL,
        subject VARCHAR(500) NOT NULL,
        body TEXT NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        priority INTEGER DEFAULT 5,
        scheduled_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        sent_at TIMESTAMP WITH TIME ZONE,
        error_message TEXT,
        retry_count INTEGER DEFAULT 0,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_queue_status ON email_queue(status);
      CREATE INDEX IF NOT EXISTS idx_queue_scheduled ON email_queue(scheduled_at);
      CREATE INDEX IF NOT EXISTS idx_queue_campaign ON email_queue(campaign_id);
    `);

    // ========================================
    // EMAIL TRACKING TABLE
    // ========================================
    await client.query(`
      CREATE TABLE IF NOT EXISTS email_tracking (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        tracking_id VARCHAR(255) UNIQUE NOT NULL,
        campaign_id UUID REFERENCES campaigns(id) ON DELETE CASCADE,
        sequence_id UUID REFERENCES sequences(id) ON DELETE CASCADE,
        sequence_step_id UUID REFERENCES sequence_steps(id) ON DELETE CASCADE,
        contact_id UUID NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
        email_queue_id UUID REFERENCES email_queue(id) ON DELETE CASCADE,
        sent_at TIMESTAMP WITH TIME ZONE,
        opened BOOLEAN DEFAULT false,
        opened_at TIMESTAMP WITH TIME ZONE,
        open_count INTEGER DEFAULT 0,
        clicked BOOLEAN DEFAULT false,
        clicked_at TIMESTAMP WITH TIME ZONE,
        click_count INTEGER DEFAULT 0,
        clicked_links JSONB DEFAULT '[]',
        replied BOOLEAN DEFAULT false,
        replied_at TIMESTAMP WITH TIME ZONE,
        bounced BOOLEAN DEFAULT false,
        bounced_at TIMESTAMP WITH TIME ZONE,
        bounce_type VARCHAR(50),
        unsubscribed BOOLEAN DEFAULT false,
        unsubscribed_at TIMESTAMP WITH TIME ZONE,
        user_agent TEXT,
        ip_address VARCHAR(50),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_tracking_id ON email_tracking(tracking_id);
      CREATE INDEX IF NOT EXISTS idx_tracking_campaign ON email_tracking(campaign_id);
      CREATE INDEX IF NOT EXISTS idx_tracking_contact ON email_tracking(contact_id);
    `);

    // ========================================
    // UNSUBSCRIBES TABLE
    // ========================================
    await client.query(`
      CREATE TABLE IF NOT EXISTS unsubscribes (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email VARCHAR(255) UNIQUE NOT NULL,
        contact_id UUID REFERENCES contacts(id) ON DELETE SET NULL,
        reason TEXT,
        source VARCHAR(100),
        ip_address VARCHAR(50),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_unsubscribes_email ON unsubscribes(email);
    `);

    // ========================================
    // ANALYTICS EVENTS TABLE
    // ========================================
    await client.query(`
      CREATE TABLE IF NOT EXISTS analytics_events (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        event_type VARCHAR(50) NOT NULL,
        campaign_id UUID REFERENCES campaigns(id) ON DELETE CASCADE,
        sequence_id UUID REFERENCES sequences(id) ON DELETE CASCADE,
        contact_id UUID REFERENCES contacts(id) ON DELETE CASCADE,
        tracking_id VARCHAR(255),
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_analytics_type ON analytics_events(event_type);
      CREATE INDEX IF NOT EXISTS idx_analytics_campaign ON analytics_events(campaign_id);
      CREATE INDEX IF NOT EXISTS idx_analytics_created ON analytics_events(created_at);
    `);

    // ========================================
    // DAILY STATS TABLE (Aggregated)
    // ========================================
    await client.query(`
      CREATE TABLE IF NOT EXISTS daily_stats (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        date DATE NOT NULL,
        emails_sent INTEGER DEFAULT 0,
        emails_delivered INTEGER DEFAULT 0,
        emails_opened INTEGER DEFAULT 0,
        emails_clicked INTEGER DEFAULT 0,
        emails_replied INTEGER DEFAULT 0,
        emails_bounced INTEGER DEFAULT 0,
        emails_unsubscribed INTEGER DEFAULT 0,
        new_contacts INTEGER DEFAULT 0,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(date)
      );
      CREATE INDEX IF NOT EXISTS idx_daily_stats_date ON daily_stats(date);
    `);

    // ========================================
    // UPDATED_AT TRIGGER
    // ========================================
    await client.query(`
      CREATE OR REPLACE FUNCTION update_updated_at_column()
      RETURNS TRIGGER AS $$
      BEGIN
        NEW.updated_at = CURRENT_TIMESTAMP;
        RETURN NEW;
      END;
      $$ language 'plpgsql';
    `);

    // Apply triggers
    const tablesWithUpdatedAt = [
      'users', 'warming_accounts', 'contacts', 'email_templates', 
      'campaigns', 'sequences'
    ];
    
    for (const table of tablesWithUpdatedAt) {
      await client.query(`
        DROP TRIGGER IF EXISTS update_${table}_updated_at ON ${table};
        CREATE TRIGGER update_${table}_updated_at BEFORE UPDATE ON ${table}
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
      `);
    }

    console.log('✅ Database migrations completed');
    
    // Create default admin user
    await createDefaultAdmin(client);
    
    // Insert default templates
    await insertDefaultTemplates(client);
    
  } catch (error) {
    console.error('❌ Migration error:', error);
    throw error;
  } finally {
    client.release();
  }
}

async function createDefaultAdmin(client) {
  try {
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@yourdomain.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'ChangeThisPassword123!';
    
    const result = await client.query('SELECT id FROM users WHERE email = $1', [adminEmail]);
    
    if (result.rows.length === 0) {
      const hashedPassword = await bcrypt.hash(adminPassword, 10);
      await client.query(
        `INSERT INTO users (email, password, name, role, active) VALUES ($1, $2, $3, $4, $5)`,
        [adminEmail, hashedPassword, 'System Administrator', 'admin', true]
      );
      console.log('✅ Default admin user created:', adminEmail);
    }
  } catch (error) {
    console.error('❌ Error creating default admin:', error);
  }
}

async function insertDefaultTemplates(client) {
  try {
    const result = await client.query('SELECT id FROM email_templates LIMIT 1');
    
    if (result.rows.length === 0) {
      const templates = [
        {
          name: 'Initial Outreach',
          subject: 'Quick question about {{company}}',
          body: `Hi {{first_name}},

I came across {{company}} and was impressed by what you're building.

I'm reaching out because I think we could help {{company}} with [your value proposition].

Would you be open to a quick 15-minute call this week to explore this?

Best regards`,
          category: 'outreach'
        },
        {
          name: 'Follow-up #1',
          subject: 'Re: Quick question about {{company}}',
          body: `Hi {{first_name}},

I wanted to follow up on my previous email. I know you're busy, so I'll keep this short.

[Reiterate key value proposition]

Would you have 15 minutes this week for a quick chat?

Best regards`,
          category: 'follow-up'
        },
        {
          name: 'Follow-up #2 (Final)',
          subject: 'Closing the loop',
          body: `Hi {{first_name}},

I haven't heard back from you, so I'll assume the timing isn't right.

If things change in the future, feel free to reach out. I'd be happy to help {{company}} with [value proposition].

Wishing you all the best!

Best regards`,
          category: 'follow-up'
        },
        {
          name: 'Meeting Request',
          subject: 'Meeting request - {{first_name}}',
          body: `Hi {{first_name}},

I'd love to schedule a quick call to discuss how we can help {{company}}.

Are you available any of these times?
- [Time option 1]
- [Time option 2]
- [Time option 3]

Looking forward to connecting!

Best regards`,
          category: 'meeting'
        }
      ];

      for (const template of templates) {
        await client.query(
          `INSERT INTO email_templates (name, subject, body, category, is_default) VALUES ($1, $2, $3, $4, $5)`,
          [template.name, template.subject, template.body, template.category, true]
        );
      }
      console.log('✅ Default email templates created');
    }
  } catch (error) {
    console.error('❌ Error creating default templates:', error);
  }
}

// ============================================================================
// GENERIC QUERY HELPERS
// ============================================================================

async function query(text, params) {
  const start = Date.now();
  try {
    const res = await pool.query(text, params);
    const duration = Date.now() - start;
    if (duration > 100) {
      console.log('Slow query', { text, duration, rows: res.rowCount });
    }
    return res;
  } catch (error) {
    console.error('Database query error:', error);
    throw error;
  }
}

// ============================================================================
// USER FUNCTIONS
// ============================================================================

async function findUserByEmail(email) {
  const result = await query('SELECT * FROM users WHERE email = $1', [email]);
  return result.rows[0];
}

async function findUserById(id) {
  const result = await query(
    'SELECT id, email, name, role, active, created_at FROM users WHERE id = $1',
    [id]
  );
  return result.rows[0];
}

async function getAllUsers() {
  const result = await query(
    'SELECT id, email, name, role, active, created_at FROM users ORDER BY created_at DESC'
  );
  return result.rows;
}

async function createUser(email, password, name, role = 'user') {
  const hashedPassword = await bcrypt.hash(password, 10);
  const result = await query(
    `INSERT INTO users (email, password, name, role, active)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING id, email, name, role, active, created_at`,
    [email, hashedPassword, name, role, true]
  );
  return result.rows[0];
}

async function updateUserStatus(id, active) {
  await query('UPDATE users SET active = $1 WHERE id = $2', [active, id]);
}

async function updateUserPassword(id, newPassword) {
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  await query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, id]);
}

// ============================================================================
// INVITATION FUNCTIONS
// ============================================================================

async function createInvitation(token, email, role, expiresAt) {
  const result = await query(
    'INSERT INTO invitations (token, email, role, expires_at) VALUES ($1, $2, $3, $4) RETURNING *',
    [token, email, role, expiresAt]
  );
  return result.rows[0];
}

async function findInvitationByToken(token) {
  const result = await query(
    'SELECT * FROM invitations WHERE token = $1 AND expires_at > NOW()',
    [token]
  );
  return result.rows[0];
}

async function getAllInvitations() {
  const result = await query(
    'SELECT * FROM invitations WHERE expires_at > NOW() ORDER BY created_at DESC'
  );
  return result.rows;
}

async function deleteInvitation(token) {
  await query('DELETE FROM invitations WHERE token = $1', [token]);
}

// ============================================================================
// WARMING ACCOUNT FUNCTIONS
// ============================================================================

async function getAllWarmingAccounts() {
  const result = await query('SELECT * FROM warming_accounts ORDER BY created_at DESC');
  return result.rows;
}

async function getActiveWarmingAccount() {
  // Get account with lowest usage today, round-robin style
  const result = await query(`
    SELECT * FROM warming_accounts 
    WHERE status = 'active' AND emails_sent_today < daily_limit
    ORDER BY emails_sent_today ASC, last_used_at ASC NULLS FIRST
    LIMIT 1
  `);
  return result.rows[0];
}

async function createWarmingAccount(data) {
  const result = await query(
    `INSERT INTO warming_accounts (email, smtp_host, smtp_port, smtp_user, smtp_pass, imap_host, imap_port)
     VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
    [data.email, data.smtp_host, data.smtp_port, data.smtp_user, data.smtp_pass, data.imap_host, data.imap_port]
  );
  return result.rows[0];
}

async function updateWarmingAccountUsage(id) {
  await query(
    `UPDATE warming_accounts SET emails_sent_today = emails_sent_today + 1, last_used_at = NOW() WHERE id = $1`,
    [id]
  );
}

async function resetDailyWarmingCounts() {
  await query('UPDATE warming_accounts SET emails_sent_today = 0');
}

async function deleteWarmingAccount(id) {
  await query('DELETE FROM warming_accounts WHERE id = $1', [id]);
}

// ============================================================================
// CONTACT FUNCTIONS
// ============================================================================

async function getAllContacts() {
  const result = await query('SELECT * FROM contacts WHERE unsubscribed = false ORDER BY created_at DESC');
  return result.rows;
}

async function getContactById(id) {
  const result = await query('SELECT * FROM contacts WHERE id = $1', [id]);
  return result.rows[0];
}

async function getContactByEmail(email) {
  const result = await query('SELECT * FROM contacts WHERE email = $1', [email]);
  return result.rows[0];
}

async function createContact(data) {
  const result = await query(
    `INSERT INTO contacts (email, first_name, last_name, company, title, tags)
     VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (email) DO UPDATE SET
       first_name = COALESCE(EXCLUDED.first_name, contacts.first_name),
       last_name = COALESCE(EXCLUDED.last_name, contacts.last_name),
       company = COALESCE(EXCLUDED.company, contacts.company),
       title = COALESCE(EXCLUDED.title, contacts.title),
       updated_at = NOW()
     RETURNING *`,
    [data.email, data.first_name, data.last_name, data.company, data.title, data.tags || []]
  );
  return result.rows[0];
}

async function bulkCreateContacts(contacts) {
  const results = [];
  for (const contact of contacts) {
    try {
      const result = await createContact(contact);
      results.push(result);
    } catch (err) {
      console.error('Error inserting contact:', contact.email, err.message);
    }
  }
  return results;
}

async function unsubscribeContact(email, reason = null, source = null, ip = null) {
  await query(
    `UPDATE contacts SET unsubscribed = true, unsubscribed_at = NOW(), status = 'unsubscribed' WHERE email = $1`,
    [email]
  );
  
  await query(
    `INSERT INTO unsubscribes (email, reason, source, ip_address)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (email) DO NOTHING`,
    [email, reason, source, ip]
  );
}

async function isUnsubscribed(email) {
  const result = await query('SELECT id FROM unsubscribes WHERE email = $1', [email]);
  return result.rows.length > 0;
}

// ============================================================================
// EMAIL TEMPLATE FUNCTIONS
// ============================================================================

async function getAllTemplates() {
  const result = await query('SELECT * FROM email_templates ORDER BY is_default DESC, created_at DESC');
  return result.rows;
}

async function getTemplateById(id) {
  const result = await query('SELECT * FROM email_templates WHERE id = $1', [id]);
  return result.rows[0];
}

async function createTemplate(data, userId) {
  const result = await query(
    `INSERT INTO email_templates (name, subject, body, category, created_by)
     VALUES ($1, $2, $3, $4, $5) RETURNING *`,
    [data.name, data.subject, data.body, data.category, userId]
  );
  return result.rows[0];
}

async function updateTemplate(id, data) {
  const result = await query(
    `UPDATE email_templates SET name = $1, subject = $2, body = $3, category = $4, updated_at = NOW()
     WHERE id = $5 RETURNING *`,
    [data.name, data.subject, data.body, data.category, id]
  );
  return result.rows[0];
}

async function deleteTemplate(id) {
  await query('DELETE FROM email_templates WHERE id = $1 AND is_default = false', [id]);
}

// ============================================================================
// CAMPAIGN FUNCTIONS
// ============================================================================

async function getAllCampaigns() {
  const result = await query('SELECT * FROM campaigns ORDER BY created_at DESC');
  return result.rows;
}

async function getCampaignById(id) {
  const result = await query('SELECT * FROM campaigns WHERE id = $1', [id]);
  return result.rows[0];
}

async function createCampaign(data, userId) {
  const result = await query(
    `INSERT INTO campaigns (name, subject, body, from_name, from_email, type, sending_rate, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
    [data.name, data.subject, data.body, data.from_name, data.from_email, data.type || 'single', data.sending_rate || 30, userId]
  );
  return result.rows[0];
}

async function updateCampaignStatus(id, status) {
  const updates = { status };
  if (status === 'sending') updates.started_at = new Date();
  if (status === 'sent' || status === 'completed') updates.completed_at = new Date();
  
  const result = await query(
    `UPDATE campaigns SET status = $1, started_at = COALESCE($2, started_at), completed_at = COALESCE($3, completed_at)
     WHERE id = $4 RETURNING *`,
    [status, updates.started_at || null, updates.completed_at || null, id]
  );
  return result.rows[0];
}

async function updateCampaignStats(id, field) {
  await query(`UPDATE campaigns SET ${field} = ${field} + 1 WHERE id = $1`, [id]);
}

// ============================================================================
// SEQUENCE FUNCTIONS
// ============================================================================

async function getAllSequences() {
  const result = await query('SELECT * FROM sequences ORDER BY created_at DESC');
  return result.rows;
}

async function getSequenceById(id) {
  const result = await query('SELECT * FROM sequences WHERE id = $1', [id]);
  return result.rows[0];
}

async function getSequenceWithSteps(id) {
  const sequence = await getSequenceById(id);
  if (!sequence) return null;
  
  const steps = await query(
    'SELECT * FROM sequence_steps WHERE sequence_id = $1 ORDER BY step_number ASC',
    [id]
  );
  
  sequence.steps = steps.rows;
  return sequence;
}

async function createSequence(data, userId) {
  const result = await query(
    `INSERT INTO sequences (name, description, from_name, from_email, created_by)
     VALUES ($1, $2, $3, $4, $5) RETURNING *`,
    [data.name, data.description, data.from_name, data.from_email, userId]
  );
  return result.rows[0];
}

async function createSequenceStep(sequenceId, data) {
  const result = await query(
    `INSERT INTO sequence_steps (sequence_id, step_number, subject, body, delay_days, delay_hours, send_if_no_reply)
     VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
    [sequenceId, data.step_number, data.subject, data.body, data.delay_days || 1, data.delay_hours || 0, data.send_if_no_reply !== false]
  );
  return result.rows[0];
}

async function addContactsToSequence(sequenceId, contactIds) {
  let added = 0;
  const now = new Date();
  
  for (const contactId of contactIds) {
    try {
      await query(
        `INSERT INTO sequence_contacts (sequence_id, contact_id, next_email_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (sequence_id, contact_id) DO NOTHING`,
        [sequenceId, contactId, now]
      );
      added++;
    } catch (err) {
      console.error('Error adding contact to sequence:', err.message);
    }
  }
  
  await query(
    'UPDATE sequences SET total_contacts = total_contacts + $1, active_contacts = active_contacts + $1 WHERE id = $2',
    [added, sequenceId]
  );
  
  return added;
}

async function getSequenceContactsDueForEmail() {
  const result = await query(`
    SELECT sc.*, s.from_name, s.from_email, c.email, c.first_name, c.last_name, c.company, c.title,
           ss.subject, ss.body
    FROM sequence_contacts sc
    JOIN sequences s ON sc.sequence_id = s.id
    JOIN contacts c ON sc.contact_id = c.id
    JOIN sequence_steps ss ON ss.sequence_id = s.id AND ss.step_number = sc.current_step
    WHERE sc.status = 'active'
      AND sc.next_email_at <= NOW()
      AND s.status = 'active'
      AND c.unsubscribed = false
    ORDER BY sc.next_email_at ASC
    LIMIT 100
  `);
  return result.rows;
}

async function updateSequenceContactAfterSend(id, nextStep, nextEmailAt) {
  if (nextStep === null) {
    // Sequence completed
    await query(
      `UPDATE sequence_contacts SET status = 'completed', completed_at = NOW(), last_email_at = NOW() WHERE id = $1`,
      [id]
    );
  } else {
    await query(
      `UPDATE sequence_contacts SET current_step = $1, next_email_at = $2, last_email_at = NOW() WHERE id = $3`,
      [nextStep, nextEmailAt, id]
    );
  }
}

// ============================================================================
// EMAIL QUEUE FUNCTIONS
// ============================================================================

async function addToEmailQueue(data) {
  const result = await query(
    `INSERT INTO email_queue (campaign_id, sequence_id, sequence_step_id, contact_id, to_email, to_name, from_email, from_name, subject, body, scheduled_at, priority)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`,
    [data.campaign_id, data.sequence_id, data.sequence_step_id, data.contact_id, data.to_email, data.to_name, data.from_email, data.from_name, data.subject, data.body, data.scheduled_at || new Date(), data.priority || 5]
  );
  return result.rows[0];
}

async function getNextQueuedEmails(limit = 10) {
  const result = await query(`
    SELECT * FROM email_queue
    WHERE status = 'pending' AND scheduled_at <= NOW() AND retry_count < 3
    ORDER BY priority ASC, scheduled_at ASC
    LIMIT $1
  `, [limit]);
  return result.rows;
}

async function updateQueueItemStatus(id, status, errorMessage = null) {
  if (status === 'failed') {
    await query(
      `UPDATE email_queue SET status = $1, error_message = $2, retry_count = retry_count + 1 WHERE id = $3`,
      [status, errorMessage, id]
    );
  } else {
    await query(
      `UPDATE email_queue SET status = $1, sent_at = CASE WHEN $1 = 'sent' THEN NOW() ELSE sent_at END WHERE id = $2`,
      [status, id]
    );
  }
}

// ============================================================================
// TRACKING FUNCTIONS
// ============================================================================

function generateTrackingId() {
  return crypto.randomBytes(16).toString('hex');
}

async function createTracking(data) {
  const trackingId = generateTrackingId();
  const result = await query(
    `INSERT INTO email_tracking (tracking_id, campaign_id, sequence_id, sequence_step_id, contact_id, email_queue_id, sent_at)
     VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING *`,
    [trackingId, data.campaign_id, data.sequence_id, data.sequence_step_id, data.contact_id, data.email_queue_id]
  );
  return result.rows[0];
}

async function recordOpen(trackingId, userAgent, ip) {
  const result = await query(`
    UPDATE email_tracking 
    SET opened = true, 
        opened_at = COALESCE(opened_at, NOW()), 
        open_count = open_count + 1,
        user_agent = $2,
        ip_address = $3
    WHERE tracking_id = $1
    RETURNING *
  `, [trackingId, userAgent, ip]);
  
  const tracking = result.rows[0];
  if (tracking) {
    if (tracking.campaign_id) {
      await updateCampaignStats(tracking.campaign_id, 'emails_opened');
    }
    await logAnalyticsEvent('open', tracking.campaign_id, tracking.sequence_id, tracking.contact_id, trackingId);
  }
  
  return tracking;
}

async function recordClick(trackingId, link, userAgent, ip) {
  const result = await query(`
    UPDATE email_tracking 
    SET clicked = true, 
        clicked_at = COALESCE(clicked_at, NOW()), 
        click_count = click_count + 1,
        clicked_links = clicked_links || $2::jsonb,
        user_agent = $3,
        ip_address = $4
    WHERE tracking_id = $1
    RETURNING *
  `, [trackingId, JSON.stringify([{ link, timestamp: new Date() }]), userAgent, ip]);
  
  const tracking = result.rows[0];
  if (tracking) {
    if (tracking.campaign_id) {
      await updateCampaignStats(tracking.campaign_id, 'emails_clicked');
    }
    await logAnalyticsEvent('click', tracking.campaign_id, tracking.sequence_id, tracking.contact_id, trackingId, { link });
  }
  
  return tracking;
}

// ============================================================================
// ANALYTICS FUNCTIONS
// ============================================================================

async function logAnalyticsEvent(eventType, campaignId, sequenceId, contactId, trackingId, metadata = {}) {
  await query(
    `INSERT INTO analytics_events (event_type, campaign_id, sequence_id, contact_id, tracking_id, metadata)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [eventType, campaignId, sequenceId, contactId, trackingId, JSON.stringify(metadata)]
  );
}

async function updateDailyStats(field) {
  const today = new Date().toISOString().split('T')[0];
  await query(`
    INSERT INTO daily_stats (date, ${field})
    VALUES ($1, 1)
    ON CONFLICT (date) DO UPDATE SET ${field} = daily_stats.${field} + 1
  `, [today]);
}

async function getDailyStats(days = 30) {
  const result = await query(`
    SELECT * FROM daily_stats
    WHERE date >= CURRENT_DATE - INTERVAL '${days} days'
    ORDER BY date ASC
  `);
  return result.rows;
}

async function getOverallStats() {
  const result = await query(`
    SELECT 
      (SELECT COUNT(*) FROM contacts WHERE unsubscribed = false) as total_contacts,
      (SELECT COUNT(*) FROM campaigns) as total_campaigns,
      (SELECT COUNT(*) FROM sequences) as total_sequences,
      (SELECT COUNT(*) FROM warming_accounts WHERE status = 'active') as active_warming_accounts,
      (SELECT COALESCE(SUM(emails_sent), 0) FROM campaigns) as total_emails_sent,
      (SELECT COALESCE(SUM(emails_opened), 0) FROM campaigns) as total_emails_opened,
      (SELECT COALESCE(SUM(emails_clicked), 0) FROM campaigns) as total_emails_clicked,
      (SELECT COALESCE(SUM(emails_replied), 0) FROM campaigns) as total_emails_replied,
      (SELECT COUNT(*) FROM unsubscribes) as total_unsubscribes
  `);
  return result.rows[0];
}

async function getCampaignAnalytics(campaignId) {
  const campaign = await getCampaignById(campaignId);
  if (!campaign) return null;
  
  const openRate = campaign.emails_sent > 0 
    ? ((campaign.emails_opened / campaign.emails_sent) * 100).toFixed(1) 
    : 0;
  const clickRate = campaign.emails_opened > 0 
    ? ((campaign.emails_clicked / campaign.emails_opened) * 100).toFixed(1) 
    : 0;
  const replyRate = campaign.emails_sent > 0 
    ? ((campaign.emails_replied / campaign.emails_sent) * 100).toFixed(1) 
    : 0;
  
  return {
    ...campaign,
    openRate,
    clickRate,
    replyRate
  };
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

async function getHealthStats() {
  try {
    const stats = await getOverallStats();
    return {
      status: 'ok',
      ...stats
    };
  } catch (error) {
    return { status: 'error', error: error.message };
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
  pool,
  query,
  runMigrations,
  
  // Users
  findUserByEmail,
  findUserById,
  getAllUsers,
  createUser,
  updateUserStatus,
  updateUserPassword,
  
  // Invitations
  createInvitation,
  findInvitationByToken,
  getAllInvitations,
  deleteInvitation,
  
  // Warming
  getAllWarmingAccounts,
  getActiveWarmingAccount,
  createWarmingAccount,
  updateWarmingAccountUsage,
  resetDailyWarmingCounts,
  deleteWarmingAccount,
  
  // Contacts
  getAllContacts,
  getContactById,
  getContactByEmail,
  createContact,
  bulkCreateContacts,
  unsubscribeContact,
  isUnsubscribed,
  
  // Templates
  getAllTemplates,
  getTemplateById,
  createTemplate,
  updateTemplate,
  deleteTemplate,
  
  // Campaigns
  getAllCampaigns,
  getCampaignById,
  createCampaign,
  updateCampaignStatus,
  updateCampaignStats,
  
  // Sequences
  getAllSequences,
  getSequenceById,
  getSequenceWithSteps,
  createSequence,
  createSequenceStep,
  addContactsToSequence,
  getSequenceContactsDueForEmail,
  updateSequenceContactAfterSend,
  
  // Queue
  addToEmailQueue,
  getNextQueuedEmails,
  updateQueueItemStatus,
  
  // Tracking
  generateTrackingId,
  createTracking,
  recordOpen,
  recordClick,
  
  // Analytics
  logAnalyticsEvent,
  updateDailyStats,
  getDailyStats,
  getOverallStats,
  getCampaignAnalytics,
  getHealthStats
};
