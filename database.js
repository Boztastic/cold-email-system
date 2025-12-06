const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function initializeDatabase() {
  const client = await pool.connect();
  try {
    // Users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        company_name VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Domains table
    await client.query(`
      CREATE TABLE IF NOT EXISTS domains (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        domain_name VARCHAR(255) NOT NULL,
        cloudflare_zone_id VARCHAR(255),
        verification_status VARCHAR(50) DEFAULT 'pending',
        warming_enabled BOOLEAN DEFAULT false,
        resend_domain_id VARCHAR(255),
        resend_verified BOOLEAN DEFAULT false,
        inbox_enabled BOOLEAN DEFAULT false,
        webhook_secret VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, domain_name)
      )
    `);

    // Email accounts table
    await client.query(`
      CREATE TABLE IF NOT EXISTS email_accounts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        domain_id UUID REFERENCES domains(id) ON DELETE CASCADE,
        email_address VARCHAR(255) NOT NULL,
        display_name VARCHAR(255),
        account_type VARCHAR(50) DEFAULT 'warming',
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(email_address)
      )
    `);

    // Warming status table
    await client.query(`
      CREATE TABLE IF NOT EXISTS warming_status (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        is_active BOOLEAN DEFAULT false,
        emails_per_day INTEGER DEFAULT 10,
        ai_frequency DECIMAL(3,2) DEFAULT 0.30,
        last_run TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id)
      )
    `);

    // Warming emails sent log
    await client.query(`
      CREATE TABLE IF NOT EXISTS warming_emails (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        from_email VARCHAR(255) NOT NULL,
        to_email VARCHAR(255) NOT NULL,
        subject VARCHAR(500),
        body TEXT,
        message_id VARCHAR(255),
        resend_id VARCHAR(255),
        status VARCHAR(50) DEFAULT 'sent',
        is_ai_generated BOOLEAN DEFAULT false,
        thread_id VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Inbox messages - stores ALL warming activity for viewing
    await client.query(`
      CREATE TABLE IF NOT EXISTS inbox_messages (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        message_type VARCHAR(50) DEFAULT 'sent',
        from_email VARCHAR(255) NOT NULL,
        to_email VARCHAR(255) NOT NULL,
        subject VARCHAR(500),
        body TEXT,
        resend_id VARCHAR(255),
        is_read BOOLEAN DEFAULT false,
        is_warming BOOLEAN DEFAULT true,
        thread_id VARCHAR(255),
        reply_to_id UUID REFERENCES inbox_messages(id),
        reply_count INTEGER DEFAULT 0,
        replied_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Threads table - groups related messages
    await client.query(`
      CREATE TABLE IF NOT EXISTS threads (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        thread_id VARCHAR(255) UNIQUE NOT NULL,
        subject VARCHAR(500),
        participants TEXT[],
        message_count INTEGER DEFAULT 1,
        last_message_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_warming BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Campaigns table
    await client.query(`
      CREATE TABLE IF NOT EXISTS campaigns (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        subject VARCHAR(500),
        body TEXT,
        status VARCHAR(50) DEFAULT 'draft',
        send_rate INTEGER DEFAULT 50,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Leads table
    await client.query(`
      CREATE TABLE IF NOT EXISTS leads (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        campaign_id UUID REFERENCES campaigns(id) ON DELETE SET NULL,
        email VARCHAR(255) NOT NULL,
        first_name VARCHAR(255),
        last_name VARCHAR(255),
        company VARCHAR(255),
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Campaign emails sent
    await client.query(`
      CREATE TABLE IF NOT EXISTS campaign_emails (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        campaign_id UUID REFERENCES campaigns(id) ON DELETE CASCADE,
        lead_id UUID REFERENCES leads(id) ON DELETE CASCADE,
        from_email VARCHAR(255),
        status VARCHAR(50) DEFAULT 'pending',
        sent_at TIMESTAMP,
        opened_at TIMESTAMP,
        clicked_at TIMESTAMP,
        replied_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Audit log
    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE SET NULL,
        action VARCHAR(100) NOT NULL,
        ip_address VARCHAR(45),
        user_agent TEXT,
        details JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('Database initialized successfully');
  } finally {
    client.release();
  }
}

module.exports = { pool, initializeDatabase };
