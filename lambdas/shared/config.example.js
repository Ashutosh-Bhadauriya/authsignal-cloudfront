'use strict';

// ============================================================
// REPLACE THESE VALUES BEFORE DEPLOYING
// Copy this file to config.js and fill in your values
// ============================================================

// Your AuthSignal API secret (from https://portal.authsignal.com)
const AUTHSIGNAL_API_SECRET = 'your-authsignal-api-secret';

// AuthSignal API hostname
const AUTHSIGNAL_API_HOST = 'api.authsignal.com';

// AES-256-CBC encryption key (32 bytes = 64 hex characters)
// Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
const ENCRYPTION_KEY = 'your-64-char-hex-encryption-key';

// AES-256-CBC initialization vector (16 bytes = 32 hex characters)
// Generate with: node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"
const ENCRYPTION_IV = 'your-32-char-hex-iv';

module.exports = {
  AUTHSIGNAL_API_SECRET,
  AUTHSIGNAL_API_HOST,
  ENCRYPTION_KEY,
  ENCRYPTION_IV,
};
