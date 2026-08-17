'use strict';

const { isStaging, stagingRecipients } = require('./staging-safety');

function enabledIntegrations(env = process.env) {
  return new Set(String(env.ENABLED_INTEGRATIONS || '')
    .split(',')
    .map(value => value.trim().toLowerCase())
    .filter(Boolean));
}

function integrationEnabled(name, env = process.env) {
  return enabledIntegrations(env).has(String(name).toLowerCase());
}

function missing(env, keys) {
  return keys.filter(key => !String(env[key] || '').trim());
}

function validateRuntimeConfig(env = process.env) {
  const errors = [];
  const baseMissing = missing(env, [
    'APP_ENVIRONMENT',
    'APP_URL',
    'SUPABASE_URL',
    'SUPABASE_SERVICE_KEY',
    'SESSION_SECRET',
    'INBOX_PASSWORD'
  ]);
  if (baseMissing.length) errors.push(`missing required variables: ${baseMissing.join(', ')}`);
  if (String(env.SESSION_SECRET || '').length < 32) errors.push('SESSION_SECRET must be at least 32 characters');
  if (String(env.INBOX_PASSWORD || '').length < 12) errors.push('INBOX_PASSWORD must be at least 12 characters');

  let appURL;
  try { appURL = new URL(env.APP_URL); } catch { errors.push('APP_URL must be a valid absolute URL'); }
  if (appURL && env.NODE_ENV === 'production' && appURL.protocol !== 'https:') {
    errors.push('APP_URL must use HTTPS in production');
  }

  if (integrationEnabled('telnyx', env)) {
    const absent = missing(env, [
      'TELNYX_API_KEY',
      'TELNYX_MESSAGING_PROFILE_ID',
      'TELNYX_PHONE_NUMBER',
      'TELNYX_PUBLIC_KEY'
    ]);
    if (absent.length) errors.push(`Telnyx enabled but incomplete: ${absent.join(', ')}`);
  }
  if (integrationEnabled('voice', env)) {
    const absent = missing(env, [
      'TELNYX_API_KEY',
      'TELNYX_PUBLIC_KEY',
      'TELNYX_PHONE_NUMBER',
      'TELNYX_VOICE_CONNECTION_ID',
      'TELNYX_IOS_SIP_USERNAME',
      'TELNYX_IOS_SIP_PASSWORD'
    ]);
    if (absent.length) errors.push(`voice enabled but incomplete: ${absent.join(', ')}`);
  }
  if (integrationEnabled('ghl', env)) {
    const absent = missing(env, ['GHL_LOCATION_ID']);
    if (absent.length) errors.push(`GHL enabled but incomplete: ${absent.join(', ')}`);
  }
  if (integrationEnabled('woocommerce', env)) {
    const absent = missing(env, ['WC_WEBHOOK_SECRET']);
    if (absent.length) errors.push(`WooCommerce enabled but incomplete: ${absent.join(', ')}`);
  }
  if (integrationEnabled('ghl-bridge', env)) {
    const absent = missing(env, ['GHL_BRIDGE_SECRET', 'GHL_LOCATION_ID']);
    if (absent.length) errors.push(`GHL bridge enabled but incomplete: ${absent.join(', ')}`);
  }
  if (integrationEnabled('openrouter', env)) {
    const absent = missing(env, [
      'OPENROUTER_API_KEY',
      'OPENROUTER_ALLOWED_MODELS',
      'OPENROUTER_ALLOWED_PROVIDERS'
    ]);
    if (absent.length) errors.push(`OpenRouter enabled but incomplete: ${absent.join(', ')}`);
  }
  if (isStaging(env) && !stagingRecipients(env).size) {
    errors.push('STAGING_ALLOWED_RECIPIENTS must contain at least one valid phone number');
  }
  if (errors.length) throw new Error(`Unsafe runtime configuration: ${errors.join('; ')}`);
  return true;
}

module.exports = { enabledIntegrations, integrationEnabled, validateRuntimeConfig };
