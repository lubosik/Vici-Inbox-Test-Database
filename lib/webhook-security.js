'use strict';

const crypto = require('crypto');

const DEFAULT_REPLAY_WINDOW_SECONDS = 300;
const GHL_ED25519_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAi2HR1srL4o18O8BRa7gVJY7G7bupbN3H9AwJrHCDiOg=
-----END PUBLIC KEY-----`;

function rawBuffer(value) {
  if (Buffer.isBuffer(value)) return value;
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  throw new Error('raw webhook body is required');
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left || ''), 'utf8');
  const b = Buffer.from(String(right || ''), 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function sha256(value) {
  return crypto.createHash('sha256').update(rawBuffer(value)).digest('hex');
}

function timestampIsCurrent(timestamp, {
  nowMs = Date.now(),
  toleranceSeconds = DEFAULT_REPLAY_WINDOW_SECONDS
} = {}) {
  if (!/^\d{9,13}$/.test(String(timestamp || ''))) return false;
  const numeric = Number(timestamp);
  const timestampMs = numeric > 10_000_000_000 ? numeric : numeric * 1000;
  return Number.isFinite(timestampMs)
    && Math.abs(nowMs - timestampMs) <= toleranceSeconds * 1000;
}

function telnyxPublicKey(value) {
  const input = String(value || '').trim();
  if (!input) throw new Error('TELNYX_PUBLIC_KEY is not configured');
  if (input.includes('BEGIN PUBLIC KEY')) return crypto.createPublicKey(input);

  let keyBytes;
  if (/^[a-f0-9]{64}$/i.test(input)) keyBytes = Buffer.from(input, 'hex');
  else {
    try { keyBytes = Buffer.from(input, 'base64'); } catch { throw new Error('invalid Telnyx public key'); }
  }

  // Mission Control has historically exposed either the raw 32-byte key or
  // an SPKI DER value. Accept both representations without weakening verify.
  if (keyBytes.length === 32) {
    keyBytes = Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      keyBytes
    ]);
  }
  return crypto.createPublicKey({ key: keyBytes, format: 'der', type: 'spki' });
}

function verifyTelnyxWebhook({
  rawBody,
  signature,
  timestamp,
  publicKey,
  nowMs = Date.now(),
  toleranceSeconds = DEFAULT_REPLAY_WINDOW_SECONDS
}) {
  if (!signature || !timestamp) return false;
  if (!timestampIsCurrent(timestamp, { nowMs, toleranceSeconds })) return false;
  try {
    const payload = Buffer.concat([
      Buffer.from(`${timestamp}|`, 'utf8'),
      rawBuffer(rawBody)
    ]);
    return crypto.verify(
      null,
      payload,
      telnyxPublicKey(publicKey),
      Buffer.from(signature, 'base64')
    );
  } catch {
    return false;
  }
}

function verifyWooCommerceWebhook(rawBody, signature, secret) {
  if (!signature || !secret) return false;
  const expected = crypto.createHmac('sha256', secret).update(rawBuffer(rawBody)).digest('base64');
  return safeEqual(signature, expected);
}

function verifyGHLWebhook(rawBody, signature, publicKey = GHL_ED25519_PUBLIC_KEY) {
  if (!signature || signature === 'N/A') return false;
  try {
    return crypto.verify(
      null,
      rawBuffer(rawBody),
      publicKey,
      Buffer.from(signature, 'base64')
    );
  } catch {
    return false;
  }
}

function verifyBearerSecret(authorization, expected) {
  if (!expected) return false;
  const match = /^Bearer\s+(.+)$/i.exec(String(authorization || ''));
  return Boolean(match && safeEqual(match[1].trim(), expected));
}

module.exports = {
  DEFAULT_REPLAY_WINDOW_SECONDS,
  GHL_ED25519_PUBLIC_KEY,
  rawBuffer,
  safeEqual,
  sha256,
  timestampIsCurrent,
  verifyBearerSecret,
  verifyGHLWebhook,
  verifyTelnyxWebhook,
  verifyWooCommerceWebhook
};
