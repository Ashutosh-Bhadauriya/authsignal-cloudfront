'use strict';

const crypto = require('crypto');
const { ENCRYPTION_KEY, ENCRYPTION_IV } = require('./config');

const ALGORITHM = 'aes-256-cbc';
const key = Buffer.from(ENCRYPTION_KEY, 'hex');
const iv = Buffer.from(ENCRYPTION_IV, 'hex');

function encrypt(text) {
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(text, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return encodeURIComponent(encrypted);
}

function decrypt(encoded) {
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  let decrypted = decipher.update(decodeURIComponent(encoded), 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

module.exports = { encrypt, decrypt };
