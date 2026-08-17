'use strict';

const { claimWebhookEvent } = require('./webhook-events');
const {
  rawBuffer,
  sha256,
  verifyBearerSecret,
  verifyGHLWebhook,
  verifyTelnyxWebhook,
  verifyWooCommerceWebhook
} = require('./webhook-security');

class WebhookBoundaryError extends Error {
  constructor(message, status = 403) {
    super(message);
    this.name = 'WebhookBoundaryError';
    this.status = status;
  }
}

function parseRawJSON(body) {
  try { return JSON.parse(rawBuffer(body).toString('utf8')); }
  catch { throw new WebhookBoundaryError('invalid webhook JSON', 400); }
}

function phoneFrom(value) {
  if (typeof value === 'string') return value;
  return value?.phone_number || null;
}

function telnyxNumberMatches(eventType, payload, expectedNumber) {
  if (!expectedNumber) return false;
  if (eventType === 'message.received') {
    const recipients = Array.isArray(payload?.to) ? payload.to : [payload?.to];
    return recipients.some(entry => phoneFrom(entry) === expectedNumber);
  }
  return phoneFrom(payload?.from) === expectedNumber;
}

async function authenticateTelnyx(req, {
  provider,
  kind,
  env = process.env,
  claim = claimWebhookEvent
}) {
  const signature = req.get('telnyx-signature-ed25519');
  const timestamp = req.get('telnyx-timestamp');
  if (!verifyTelnyxWebhook({
    rawBody: req.body,
    signature,
    timestamp,
    publicKey: env.TELNYX_PUBLIC_KEY
  })) throw new WebhookBoundaryError('invalid Telnyx webhook signature');

  const body = parseRawJSON(req.body);
  const event = body?.data;
  if (!event?.id || !event?.event_type || !event?.payload) {
    throw new WebhookBoundaryError('invalid Telnyx event envelope', 400);
  }

  if (kind === 'messaging') {
    if (!env.TELNYX_MESSAGING_PROFILE_ID
        || event.payload.messaging_profile_id !== env.TELNYX_MESSAGING_PROFILE_ID) {
      throw new WebhookBoundaryError('Telnyx messaging profile mismatch');
    }
    if (!telnyxNumberMatches(event.event_type, event.payload, env.TELNYX_PHONE_NUMBER)) {
      throw new WebhookBoundaryError('Telnyx business number mismatch');
    }
  } else if (kind === 'voice') {
    if (!env.TELNYX_VOICE_CONNECTION_ID
        || event.payload.connection_id !== env.TELNYX_VOICE_CONNECTION_ID) {
      throw new WebhookBoundaryError('Telnyx voice connection mismatch');
    }
  } else {
    throw new WebhookBoundaryError('unknown Telnyx webhook kind', 500);
  }

  const replay = await claim({ provider, eventId: event.id, rawBody: req.body });
  return { body, event, duplicate: replay.duplicate };
}

async function authenticateWooCommerce(req, {
  provider = 'woocommerce',
  env = process.env,
  claim = claimWebhookEvent
} = {}) {
  if (!verifyWooCommerceWebhook(
    req.body,
    req.get('x-wc-webhook-signature'),
    env.WC_WEBHOOK_SECRET
  )) throw new WebhookBoundaryError('invalid WooCommerce webhook signature');

  const body = parseRawJSON(req.body);
  const topic = req.get('x-wc-webhook-topic') || 'unknown';
  const deliveryID = req.get('x-wc-webhook-delivery-id') || sha256(req.body);
  const replay = await claim({
    provider,
    eventId: `${topic}:${deliveryID}`,
    rawBody: req.body
  });
  return { body, topic, duplicate: replay.duplicate };
}

async function authenticateGHL(req, {
  env = process.env,
  claim = claimWebhookEvent,
  verify = verifyGHLWebhook
} = {}) {
  if (!env.GHL_LOCATION_ID) {
    throw new WebhookBoundaryError('GHL location is not configured', 503);
  }
  if (!verify(req.body, req.get('x-ghl-signature'))) {
    throw new WebhookBoundaryError('invalid GHL webhook signature');
  }
  const body = parseRawJSON(req.body);
  if (body.locationId !== env.GHL_LOCATION_ID) {
    throw new WebhookBoundaryError('GHL location mismatch');
  }
  const stableID = body.webhookId || body.eventId || sha256(req.body);
  const replay = await claim({
    provider: 'ghl',
    eventId: `${body.type || 'event'}:${stableID}`,
    rawBody: req.body
  });
  return { body, duplicate: replay.duplicate };
}

async function authenticateGHLBridge(req, {
  env = process.env,
  claim = claimWebhookEvent
} = {}) {
  if (!verifyBearerSecret(req.get('authorization'), env.GHL_BRIDGE_SECRET)) {
    throw new WebhookBoundaryError('invalid GHL bridge authorization', 401);
  }
  const idempotencyKey = req.get('idempotency-key');
  if (!idempotencyKey) throw new WebhookBoundaryError('idempotency key required', 400);
  const body = parseRawJSON(req.body);
  const replay = await claim({
    provider: 'ghl-bridge',
    eventId: idempotencyKey,
    rawBody: req.body
  });
  return { body, duplicate: replay.duplicate };
}

function rejectWebhook(res, error, label) {
  const status = error instanceof WebhookBoundaryError ? error.status : 503;
  console.warn(`[SECURITY] ${label} webhook rejected (${status})`);
  return res.status(status).json({ error: 'Webhook rejected' });
}

module.exports = {
  WebhookBoundaryError,
  authenticateGHL,
  authenticateGHLBridge,
  authenticateTelnyx,
  authenticateWooCommerce,
  parseRawJSON,
  rejectWebhook,
  telnyxNumberMatches
};
