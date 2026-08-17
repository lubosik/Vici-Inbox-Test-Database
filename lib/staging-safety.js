'use strict';

const { normalisePhone } = require('./phone');

function appEnvironment(env = process.env) {
  return String(env.APP_ENVIRONMENT || env.NODE_ENV || 'development').trim().toLowerCase();
}

function isStaging(env = process.env) {
  return appEnvironment(env) === 'staging';
}

function stagingRecipients(env = process.env) {
  return new Set(String(env.STAGING_ALLOWED_RECIPIENTS || '')
    .split(',')
    .map(value => normalisePhone(value.trim()))
    .filter(Boolean));
}

function assertStagingRecipient(value, env = process.env) {
  const phone = normalisePhone(value);
  if (!phone) throw new Error('A valid E.164 recipient is required');
  if (!isStaging(env)) return phone;

  const allowed = stagingRecipients(env);
  if (!allowed.size) throw new Error('Staging outbound messaging is locked: no recipient allowlist is configured');
  if (!allowed.has(phone)) throw new Error('Staging outbound messaging is restricted to approved test recipients');
  return phone;
}

function stagingWebhookURL(env = process.env) {
  if (!isStaging(env)) return null;
  let appURL;
  try { appURL = new URL(env.APP_URL); } catch { throw new Error('A valid APP_URL is required in staging'); }
  if (appURL.protocol !== 'https:') throw new Error('Staging APP_URL must use HTTPS');
  return new URL('/webhook/telnyx', appURL).toString();
}

module.exports = {
  appEnvironment,
  assertStagingRecipient,
  isStaging,
  stagingRecipients,
  stagingWebhookURL
};
