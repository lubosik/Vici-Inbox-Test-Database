'use strict';

const { supabase } = require('../db');
const { sha256 } = require('./webhook-security');

function validIdentifier(value) {
  return typeof value === 'string' && /^[A-Za-z0-9:._-]{1,240}$/.test(value);
}

async function claimWebhookEvent({ provider, eventId, rawBody, client = supabase }) {
  if (!validIdentifier(provider) || !validIdentifier(eventId)) {
    throw new Error('webhook event has no safe id');
  }
  const { error } = await client.from('webhook_events').insert({
    provider,
    event_id: eventId,
    payload_sha256: sha256(rawBody),
    received_at: new Date().toISOString()
  });
  if (!error) return { claimed: true, duplicate: false };
  if (error.code === '23505') return { claimed: false, duplicate: true };
  throw new Error(`webhook replay store unavailable: ${error.message}`);
}

module.exports = { claimWebhookEvent, validIdentifier };
