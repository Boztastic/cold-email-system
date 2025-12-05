// ============================================================================
// Database Connection and Migration Module
// PostgreSQL with connection pooling
// ============================================================================

const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

// ============================================================================
// DATABASE CONNECTION POOL
// ============================================================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20, // Maximum number of clients in pool
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Log pool errors
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
// MIGRATION FUNCTIONS
// ============================================================================

async function runMigrations() {
  const client = await pool.connect();
  
  try {
    console.log('🔄 Running database migrations...');
    
    // Enable UUID extension
    await client.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');
    
    // Create users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL DEFAULT 'user',
        active BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT users_email_check CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
        CONSTRAINT users_role_check CHECK (role IN ('admin', 'user'))
      );
      
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
      CREATE INDEX IF NOT EXISTS idx_users_active ON users(active);
    `);
    
    // Create invitations table
    await client.query(`
      CREATE TABLE IF NOT EXISTS invitations (
        token VARCHAR(255) PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        role VARCHAR(50) NOT NULL DEFAULT 'user',
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT invitations_email_check CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
        CONSTRAINT invitations_role_check CHECK (role IN ('admin', 'user'))
      );
      
      CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations(email);
      CREATE INDEX IF NOT EXISTS idx_invitations_expires ON invitations(expires_at);
    `);
    
    // Create warming_accounts table
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
        current_count INTEGER DEFAULT 0,
        last_email_at TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT warming_accounts_status_check CHECK (status IN ('active', 'paused', 'error'))
      );
      
      CREATE INDEX IF NOT EXISTS idx_warming_accounts_email ON warming_accounts(email);
      CREATE INDEX IF NOT EXISTS idx_warming_accounts_status ON warming_accounts(status);
    `);
    
    // Create warming_campaigns table
    await client.query(`
      CREATE TABLE IF NOT EXISTS warming_campaigns (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        account_id UUID NOT NULL REFERENCES warming_accounts(id) ON DELETE CASCADE,
        status VARCHAR(50) NOT NULL DEFAULT 'active',
        emails_sent INTEGER DEFAULT 0,
        emails_received INTEGER DEFAULT 0,
        started_at TIMESTAMP WITH TIME ZONE,
        stopped_at TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT warming_campaigns_status_check CHECK (status IN ('active', 'paused', 'stopped'))
      );
      
      CREATE INDEX IF NOT EXISTS idx_warming_campaigns_account ON warming_campaigns(account_id);
      CREATE INDEX IF NOT EXISTS idx_warming_campaigns_status ON warming_campaigns(status);
    `);
    
    // Create contacts table
    await client.query(`
      CREATE TABLE IF NOT EXISTS contacts (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email VARCHAR(255) UNIQUE NOT NULL,
        first_name VARCHAR(255),
        last_name VARCHAR(255),
        company VARCHAR(255),
        title VARCHAR(255),
        phone VARCHAR(50),
        custom_fields JSONB,
        tags TEXT[],
        status VARCHAR(50) DEFAULT 'active',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT contacts_email_check CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
        CONSTRAINT contacts_status_check CHECK (status IN ('active', 'unsubscribed', 'bounced'))
      );
      
      CREATE INDEX IF NOT EXISTS idx_contacts_email ON contacts(email);
      CREATE INDEX IF NOT EXISTS idx_contacts_status ON contacts(status);
    `);
    
    // Create campaigns table
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
        scheduled_at TIMESTAMP WITH TIME ZONE,
        started_at TIMESTAMP WITH TIME ZONE,
        completed_at TIMESTAMP WITH TIME ZONE,
        total_recipients INTEGER DEFAULT 0,
        emails_sent INTEGER DEFAULT 0,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT campaigns_status_check CHECK (status IN ('draft', 'scheduled', 'sending', 'sent', 'paused', 'cancelled'))
      );
      
      CREATE INDEX IF NOT EXISTS idx_campaigns_status ON campaigns(status);
    `);
    
    // Create updated_at trigger function
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
    const tables = ['users', 'warming_accounts', 'warming_campaigns', 'contacts', 'campaigns'];
    for (const table of tables) {
      await client.query(`
        DROP TRIGGER IF EXISTS update_${table}_updated_at ON ${table};
        CREATE TRIGGER update_${table}_updated_at BEFORE UPDATE ON ${table}
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
      `);
    }
    
    console.log('✅ Database migrations completed');
    
    // Create default admin user if it doesn't exist
    await createDefaultAdmin(client);
    
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
    
    // Check if admin exists
    const result = await client.query(
      'SELECT id FROM users WHERE email = $1',
      [adminEmail]
    );
    
    if (result.rows.length === 0) {
      // Create admin user
      const hashedPassword = await bcrypt.hash(adminPassword, 10);
      
      await client.query(
        `INSERT INTO users (email, password, name, role, active)
         VALUES ($1, $2, $3, $4, $5)`,
        [adminEmail, hashedPassword, 'System Administrator', 'admin', true]
      );
      
      console.log('✅ Default admin user created:', adminEmail);
      console.log('⚠️  Please change the default password immediately!');
    } else {
      console.log('ℹ️  Admin user already exists');
    }
  } catch (error) {
    console.error('❌ Error creating default admin:', error);
  }
}

// ============================================================================
// DATABASE HELPER FUNCTIONS
// ============================================================================

// Generic query function with error handling
async function query(text, params) {
  const start = Date.now();
  try {
    const res = await pool.query(text, params);
    const duration = Date.now() - start;
    console.log('Executed query', { text, duration, rows: res.rowCount });
    return res;
  } catch (error) {
    console.error('Database query error:', error);
    throw error;
  }
}

// Transaction helper
async function transaction(callback) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

// ============================================================================
// USER QUERIES
// ============================================================================

async function findUserByEmail(email) {
  const result = await query(
    'SELECT * FROM users WHERE email = $1',
    [email]
  );
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
  const result = await query(
    'UPDATE users SET active = $1 WHERE id = $2 RETURNING id',
    [active, id]
  );
  return result.rows[0];
}

async function updateUserPassword(id, newPassword) {
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  await query(
    'UPDATE users SET password = $1 WHERE id = $2',
    [hashedPassword, id]
  );
}

// ============================================================================
// INVITATION QUERIES
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
// WARMING ACCOUNT QUERIES
// ============================================================================

async function getAllWarmingAccounts() {
  const result = await query(
    'SELECT * FROM warming_accounts ORDER BY created_at DESC'
  );
  return result.rows;
}

async function createWarmingAccount(accountData) {
  const { email, smtp_host, smtp_port, smtp_user, smtp_pass, imap_host, imap_port } = accountData;
  const result = await query(
    `INSERT INTO warming_accounts 
     (email, smtp_host, smtp_port, smtp_user, smtp_pass, imap_host, imap_port, status)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     RETURNING *`,
    [email, smtp_host, smtp_port, smtp_user, smtp_pass, imap_host, imap_port, 'active']
  );
  return result.rows[0];
}

async function deleteWarmingAccount(id) {
  await query('DELETE FROM warming_accounts WHERE id = $1', [id]);
}

// ============================================================================
// CONTACT QUERIES
// ============================================================================

async function getAllContacts() {
  const result = await query(
    'SELECT * FROM contacts ORDER BY created_at DESC'
  );
  return result.rows;
}

async function createContact(contactData) {
  const { email, first_name, last_name, company, title } = contactData;
  const result = await query(
    `INSERT INTO contacts (email, first_name, last_name, company, title)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING *`,
    [email, first_name, last_name, company, title]
  );
  return result.rows[0];
}

async function bulkCreateContacts(contacts) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const insertedContacts = [];
    for (const contact of contacts) {
      try {
        const result = await client.query(
          `INSERT INTO contacts (email, first_name, last_name, company, title)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (email) DO NOTHING
           RETURNING *`,
          [contact.email, contact.first_name, contact.last_name, contact.company, contact.title]
        );
        if (result.rows[0]) {
          insertedContacts.push(result.rows[0]);
        }
      } catch (err) {
        console.error('Error inserting contact:', contact.email, err);
      }
    }
    
    await client.query('COMMIT');
    return insertedContacts;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

// ============================================================================
// CAMPAIGN QUERIES
// ============================================================================

async function getAllCampaigns() {
  const result = await query(
    'SELECT * FROM campaigns ORDER BY created_at DESC'
  );
  return result.rows;
}

async function createCampaign(campaignData) {
  const { name, subject, body, from_name, from_email } = campaignData;
  const result = await query(
    `INSERT INTO campaigns (name, subject, body, from_name, from_email, status)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING *`,
    [name, subject, body, from_name, from_email, 'draft']
  );
  return result.rows[0];
}

async function updateCampaignStatus(id, status) {
  const result = await query(
    'UPDATE campaigns SET status = $1 WHERE id = $2 RETURNING *',
    [status, id]
  );
  return result.rows[0];
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

async function getHealthStats() {
  try {
    const [campaignsResult, warmingAccountsResult, warmingCampaignsResult] = await Promise.all([
      query('SELECT COUNT(*) FROM campaigns'),
      query('SELECT COUNT(*) FROM warming_accounts'),
      query('SELECT COUNT(*) FROM warming_campaigns WHERE status = $1', ['active'])
    ]);
    
    return {
      status: 'ok',
      campaigns: parseInt(campaignsResult.rows[0].count),
      warmingAccounts: parseInt(warmingAccountsResult.rows[0].count),
      warmingCampaigns: parseInt(warmingCampaignsResult.rows[0].count),
      queueLength: 0
    };
  } catch (error) {
    return {
      status: 'error',
      error: error.message
    };
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
  pool,
  query,
  transaction,
  runMigrations,
  
  // User functions
  findUserByEmail,
  findUserById,
  getAllUsers,
  createUser,
  updateUserStatus,
  updateUserPassword,
  
  // Invitation functions
  createInvitation,
  findInvitationByToken,
  getAllInvitations,
  deleteInvitation,
  
  // Warming account functions
  getAllWarmingAccounts,
  createWarmingAccount,
  deleteWarmingAccount,
  
  // Contact functions
  getAllContacts,
  createContact,
  bulkCreateContacts,
  
  // Campaign functions
  getAllCampaigns,
  createCampaign,
  updateCampaignStatus,
  
  // Health
  getHealthStats
};
