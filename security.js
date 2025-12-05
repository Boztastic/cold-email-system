// ============================================================================
// SECURITY UTILITIES MODULE
// Encryption, Validation, Sanitization, and Protection
// ============================================================================

const crypto = require('crypto');

// ============================================================================
// ENCRYPTION (AES-256-GCM)
// ============================================================================

// Get encryption key from environment or generate warning
function getEncryptionKey() {
  const key = process.env.ENCRYPTION_KEY;
  if (!key) {
    console.error('⚠️  WARNING: ENCRYPTION_KEY not set! Using insecure default.');
    console.error('   Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
    // Return a default key for development only - NEVER use in production
    return crypto.scryptSync('insecure-dev-key', 'salt', 32);
  }
  // Convert hex key to buffer
  if (key.length === 64) {
    return Buffer.from(key, 'hex');
  }
  // If not hex, derive key from passphrase
  return crypto.scryptSync(key, 'cold-email-salt', 32);
}

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

/**
 * Encrypt sensitive data
 * @param {string} plaintext - Data to encrypt
 * @returns {string} - Encrypted data as hex string (iv:authTag:ciphertext)
 */
function encrypt(plaintext) {
  if (!plaintext) return null;
  
  try {
    const key = getEncryptionKey();
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    // Format: iv:authTag:ciphertext (all hex)
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  } catch (error) {
    console.error('Encryption error:', error.message);
    throw new Error('Failed to encrypt data');
  }
}

/**
 * Decrypt sensitive data
 * @param {string} encryptedData - Encrypted data from encrypt()
 * @returns {string} - Original plaintext
 */
function decrypt(encryptedData) {
  if (!encryptedData) return null;
  
  // Check if data is encrypted (contains colons)
  if (!encryptedData.includes(':')) {
    // Return as-is for legacy unencrypted data
    console.warn('Warning: Unencrypted data detected. Consider re-encrypting.');
    return encryptedData;
  }
  
  try {
    const key = getEncryptionKey();
    const [ivHex, authTagHex, ciphertext] = encryptedData.split(':');
    
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error.message);
    throw new Error('Failed to decrypt data - key may have changed');
  }
}

/**
 * Check if a string is already encrypted
 * @param {string} data - Data to check
 * @returns {boolean}
 */
function isEncrypted(data) {
  if (!data) return false;
  const parts = data.split(':');
  return parts.length === 3 && 
         parts[0].length === IV_LENGTH * 2 && 
         parts[1].length === AUTH_TAG_LENGTH * 2;
}

// ============================================================================
// INPUT VALIDATION
// ============================================================================

const validators = {
  /**
   * Validate email format
   */
  email: (email) => {
    if (!email || typeof email !== 'string') return false;
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    return emailRegex.test(email) && email.length <= 254;
  },

  /**
   * Validate password strength
   * - Minimum 8 characters
   * - At least one uppercase
   * - At least one lowercase
   * - At least one number
   * - At least one special character
   */
  password: (password) => {
    if (!password || typeof password !== 'string') return { valid: false, message: 'Password is required' };
    
    const checks = [
      { test: password.length >= 8, message: 'Password must be at least 8 characters' },
      { test: password.length <= 128, message: 'Password must be less than 128 characters' },
      { test: /[a-z]/.test(password), message: 'Password must contain a lowercase letter' },
      { test: /[A-Z]/.test(password), message: 'Password must contain an uppercase letter' },
      { test: /[0-9]/.test(password), message: 'Password must contain a number' },
      { test: /[!@#$%^&*(),.?":{}|<>]/.test(password), message: 'Password must contain a special character (!@#$%^&*...)' },
    ];
    
    for (const check of checks) {
      if (!check.test) return { valid: false, message: check.message };
    }
    
    return { valid: true };
  },

  /**
   * Validate domain name
   */
  domain: (domain) => {
    if (!domain || typeof domain !== 'string') return false;
    const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    return domainRegex.test(domain) && domain.length <= 253;
  },

  /**
   * Validate URL
   */
  url: (url) => {
    if (!url || typeof url !== 'string') return false;
    try {
      new URL(url);
      return url.length <= 2048;
    } catch {
      return false;
    }
  },

  /**
   * Validate UUID
   */
  uuid: (uuid) => {
    if (!uuid || typeof uuid !== 'string') return false;
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
  },

  /**
   * Validate and sanitize string length
   */
  maxLength: (str, max) => {
    if (!str) return true;
    return typeof str === 'string' && str.length <= max;
  },

  /**
   * Validate port number
   */
  port: (port) => {
    const num = parseInt(port);
    return !isNaN(num) && num >= 1 && num <= 65535;
  },

  /**
   * Validate hostname
   */
  hostname: (hostname) => {
    if (!hostname || typeof hostname !== 'string') return false;
    const hostnameRegex = /^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$/;
    return hostnameRegex.test(hostname) && hostname.length <= 255;
  }
};

// ============================================================================
// INPUT SANITIZATION
// ============================================================================

const sanitizers = {
  /**
   * Sanitize HTML to prevent XSS in emails
   * Allows safe HTML tags, removes dangerous ones
   */
  html: (html) => {
    if (!html) return '';
    
    // Remove script tags and their contents
    html = html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
    
    // Remove event handlers (onclick, onload, onerror, etc.)
    html = html.replace(/\s*on\w+\s*=\s*["'][^"']*["']/gi, '');
    html = html.replace(/\s*on\w+\s*=\s*[^\s>]*/gi, '');
    
    // Remove javascript: links
    html = html.replace(/href\s*=\s*["']javascript:[^"']*["']/gi, 'href="#"');
    
    // Remove data: links (potential XSS vector)
    html = html.replace(/href\s*=\s*["']data:[^"']*["']/gi, 'href="#"');
    
    // Remove style tags (can contain expressions)
    html = html.replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '');
    
    // Remove iframe, object, embed, form
    html = html.replace(/<(iframe|object|embed|form)[^>]*>.*?<\/\1>/gi, '');
    html = html.replace(/<(iframe|object|embed|form)[^>]*\/?>/gi, '');
    
    return html;
  },

  /**
   * Sanitize plain text - remove any HTML
   */
  text: (text) => {
    if (!text) return '';
    return text
      .replace(/<[^>]*>/g, '')  // Remove all HTML tags
      .replace(/&nbsp;/g, ' ')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .trim();
  },

  /**
   * Sanitize for SQL (extra layer, even with parameterized queries)
   */
  sqlString: (str) => {
    if (!str) return '';
    return str.replace(/'/g, "''");
  },

  /**
   * Trim and normalize whitespace
   */
  normalize: (str) => {
    if (!str) return '';
    return str.trim().replace(/\s+/g, ' ');
  },

  /**
   * Sanitize email subject
   */
  subject: (subject) => {
    if (!subject) return '';
    // Remove newlines (header injection prevention)
    return subject.replace(/[\r\n]/g, '').substring(0, 998);
  },

  /**
   * Sanitize filename
   */
  filename: (filename) => {
    if (!filename) return '';
    return filename
      .replace(/[^a-zA-Z0-9._-]/g, '_')
      .substring(0, 255);
  }
};

// ============================================================================
// BRUTE FORCE PROTECTION
// ============================================================================

class LoginAttemptTracker {
  constructor(options = {}) {
    this.attempts = new Map();
    this.maxAttempts = options.maxAttempts || 5;
    this.lockoutDuration = options.lockoutDuration || 15 * 60 * 1000; // 15 minutes
    this.attemptWindow = options.attemptWindow || 15 * 60 * 1000; // 15 minutes
    
    // Clean up old entries every 5 minutes
    setInterval(() => this.cleanup(), 5 * 60 * 1000);
  }

  /**
   * Get key for tracking (IP + email combination)
   */
  getKey(ip, email) {
    return `${ip}:${email?.toLowerCase()}`;
  }

  /**
   * Record a failed login attempt
   */
  recordFailure(ip, email) {
    const key = this.getKey(ip, email);
    const now = Date.now();
    
    let record = this.attempts.get(key);
    if (!record) {
      record = { attempts: [], lockedUntil: null };
      this.attempts.set(key, record);
    }
    
    // Add new attempt
    record.attempts.push(now);
    
    // Remove old attempts outside window
    record.attempts = record.attempts.filter(t => now - t < this.attemptWindow);
    
    // Check if should lock
    if (record.attempts.length >= this.maxAttempts) {
      record.lockedUntil = now + this.lockoutDuration;
      record.attempts = []; // Clear attempts after lockout
    }
    
    return this.getRemainingAttempts(ip, email);
  }

  /**
   * Record a successful login (clears attempts)
   */
  recordSuccess(ip, email) {
    const key = this.getKey(ip, email);
    this.attempts.delete(key);
  }

  /**
   * Check if account/IP is locked out
   */
  isLocked(ip, email) {
    const key = this.getKey(ip, email);
    const record = this.attempts.get(key);
    
    if (!record || !record.lockedUntil) return false;
    
    if (Date.now() > record.lockedUntil) {
      // Lockout expired
      record.lockedUntil = null;
      return false;
    }
    
    return true;
  }

  /**
   * Get remaining time on lockout (in seconds)
   */
  getLockoutRemaining(ip, email) {
    const key = this.getKey(ip, email);
    const record = this.attempts.get(key);
    
    if (!record || !record.lockedUntil) return 0;
    
    const remaining = record.lockedUntil - Date.now();
    return remaining > 0 ? Math.ceil(remaining / 1000) : 0;
  }

  /**
   * Get remaining attempts before lockout
   */
  getRemainingAttempts(ip, email) {
    const key = this.getKey(ip, email);
    const record = this.attempts.get(key);
    
    if (!record) return this.maxAttempts;
    if (record.lockedUntil && Date.now() < record.lockedUntil) return 0;
    
    return Math.max(0, this.maxAttempts - record.attempts.length);
  }

  /**
   * Clean up old entries
   */
  cleanup() {
    const now = Date.now();
    for (const [key, record] of this.attempts.entries()) {
      // Remove if no recent attempts and not locked
      if (record.attempts.length === 0 && 
          (!record.lockedUntil || now > record.lockedUntil)) {
        this.attempts.delete(key);
      }
    }
  }
}

// Create singleton instance
const loginTracker = new LoginAttemptTracker();

// ============================================================================
// RATE LIMITING BY USER
// ============================================================================

class UserRateLimiter {
  constructor(options = {}) {
    this.requests = new Map();
    this.maxRequests = options.maxRequests || 100;
    this.windowMs = options.windowMs || 60 * 1000; // 1 minute
    
    setInterval(() => this.cleanup(), 60 * 1000);
  }

  /**
   * Check if user is rate limited
   */
  isLimited(userId) {
    const now = Date.now();
    let record = this.requests.get(userId);
    
    if (!record) {
      record = { count: 0, windowStart: now };
      this.requests.set(userId, record);
    }
    
    // Reset window if expired
    if (now - record.windowStart > this.windowMs) {
      record.count = 0;
      record.windowStart = now;
    }
    
    record.count++;
    
    return record.count > this.maxRequests;
  }

  /**
   * Get remaining requests
   */
  getRemaining(userId) {
    const record = this.requests.get(userId);
    if (!record) return this.maxRequests;
    
    const now = Date.now();
    if (now - record.windowStart > this.windowMs) return this.maxRequests;
    
    return Math.max(0, this.maxRequests - record.count);
  }

  cleanup() {
    const now = Date.now();
    for (const [userId, record] of this.requests.entries()) {
      if (now - record.windowStart > this.windowMs) {
        this.requests.delete(userId);
      }
    }
  }
}

const userRateLimiter = new UserRateLimiter();

// ============================================================================
// SECURITY HEADERS CONFIGURATION
// ============================================================================

const securityHeaders = {
  // Content Security Policy
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    }
  },
  
  // Other security headers
  headers: {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
  }
};

// ============================================================================
// AUDIT LOGGING
// ============================================================================

function createAuditLog(action, userId, details = {}, req = null) {
  const log = {
    timestamp: new Date().toISOString(),
    action,
    userId,
    ip: req?.ip || req?.connection?.remoteAddress || 'unknown',
    userAgent: req?.headers?.['user-agent'] || 'unknown',
    details
  };
  
  // In production, you'd want to store this in the database
  console.log('AUDIT:', JSON.stringify(log));
  
  return log;
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
  // Encryption
  encrypt,
  decrypt,
  isEncrypted,
  
  // Validation
  validators,
  
  // Sanitization
  sanitizers,
  
  // Brute force protection
  loginTracker,
  
  // Rate limiting
  userRateLimiter,
  
  // Security config
  securityHeaders,
  
  // Audit logging
  createAuditLog
};
