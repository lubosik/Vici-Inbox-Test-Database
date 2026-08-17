'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

process.env.SUPABASE_URL ||= 'https://unit-test.supabase.co';
process.env.SUPABASE_SERVICE_KEY ||= 'unit-test-service-key';

const { sendSMS } = require('../telnyx');
const { authenticateGHL, authenticateTelnyx } = require('../lib/webhook-boundary');
const { claimWebhookEvent } = require('../lib/webhook-events');
const { originAllowed } = require('../lib/request-security');
const { validateRuntimeConfig } = require('../lib/runtime-config');
const {
  verifyGHLWebhook,
  verifyTelnyxWebhook,
  verifyWooCommerceWebhook
} = require('../lib/webhook-security');

function telnyxFixture({ ageSeconds = 0, eventType = 'message.received', payload = null } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const timestamp = String(Math.floor(Date.now() / 1000) - ageSeconds);
  const body = Buffer.from(JSON.stringify({
    data: {
      id: 'evt-test-1',
      event_type: eventType,
      payload: payload || {
        id: 'message-1',
        messaging_profile_id: 'profile-test',
        from: { phone_number: '+15555550100' },
        to: [{ phone_number: '+15555550199' }],
        text: 'Test only'
      }
    }
  }));
  const signature = crypto.sign(
    null,
    Buffer.concat([Buffer.from(`${timestamp}|`), body]),
    privateKey
  ).toString('base64');
  return {
    body,
    signature,
    timestamp,
    publicKey: publicKey.export({ type: 'spki', format: 'pem' })
  };
}

test('Telnyx Ed25519 verification accepts a current payload and rejects tampering or replay', () => {
  const fixture = telnyxFixture();
  assert.equal(verifyTelnyxWebhook({
    rawBody: fixture.body,
    signature: fixture.signature,
    timestamp: fixture.timestamp,
    publicKey: fixture.publicKey
  }), true);
  assert.equal(verifyTelnyxWebhook({
    rawBody: Buffer.from(`${fixture.body} `),
    signature: fixture.signature,
    timestamp: fixture.timestamp,
    publicKey: fixture.publicKey
  }), false);
  assert.equal(verifyTelnyxWebhook({
    rawBody: fixture.body,
    signature: '',
    timestamp: fixture.timestamp,
    publicKey: fixture.publicKey
  }), false);

  const stale = telnyxFixture({ ageSeconds: 301 });
  assert.equal(verifyTelnyxWebhook({
    rawBody: stale.body,
    signature: stale.signature,
    timestamp: stale.timestamp,
    publicKey: stale.publicKey
  }), false);
});

test('Telnyx boundary binds a signed message to the configured profile and business number', async () => {
  const fixture = telnyxFixture();
  const headers = {
    'telnyx-signature-ed25519': fixture.signature,
    'telnyx-timestamp': fixture.timestamp
  };
  const request = { body: fixture.body, get: name => headers[name.toLowerCase()] };
  const env = {
    TELNYX_PUBLIC_KEY: fixture.publicKey,
    TELNYX_MESSAGING_PROFILE_ID: 'profile-test',
    TELNYX_PHONE_NUMBER: '+15555550199'
  };
  const verified = await authenticateTelnyx(request, {
    provider: 'telnyx-messaging',
    kind: 'messaging',
    env,
    claim: async () => ({ duplicate: false })
  });
  assert.equal(verified.event.id, 'evt-test-1');

  await assert.rejects(
    authenticateTelnyx(request, {
      provider: 'telnyx-messaging',
      kind: 'messaging',
      env: { ...env, TELNYX_MESSAGING_PROFILE_ID: 'wrong-profile' },
      claim: async () => ({ duplicate: false })
    }),
    /profile mismatch/
  );
  await assert.rejects(
    authenticateTelnyx(request, {
      provider: 'telnyx-messaging',
      kind: 'messaging',
      env: { ...env, TELNYX_PHONE_NUMBER: '+15555550200' },
      claim: async () => ({ duplicate: false })
    }),
    /business number mismatch/
  );
});

test('Telnyx voice boundary binds signed events to the configured connection', async () => {
  const fixture = telnyxFixture({
    eventType: 'call.initiated',
    payload: {
      call_control_id: 'call-test-1',
      connection_id: 'connection-test',
      from: '+15555550100',
      to: '+15555550199',
      direction: 'incoming'
    }
  });
  const headers = {
    'telnyx-signature-ed25519': fixture.signature,
    'telnyx-timestamp': fixture.timestamp
  };
  const request = { body: fixture.body, get: name => headers[name.toLowerCase()] };
  const options = {
    provider: 'telnyx-voice',
    kind: 'voice',
    env: {
      TELNYX_PUBLIC_KEY: fixture.publicKey,
      TELNYX_VOICE_CONNECTION_ID: 'connection-test'
    },
    claim: async () => ({ duplicate: false })
  };
  const verified = await authenticateTelnyx(request, options);
  assert.equal(verified.event.event_type, 'call.initiated');
  await assert.rejects(
    authenticateTelnyx(request, {
      ...options,
      env: { ...options.env, TELNYX_VOICE_CONNECTION_ID: 'wrong-connection' }
    }),
    /connection mismatch/
  );
});

test('persistent replay claims deduplicate and fail closed when storage is unavailable', async () => {
  const rawBody = Buffer.from('{"event":"test"}');
  const duplicateClient = {
    from: () => ({ insert: async () => ({ error: { code: '23505', message: 'duplicate' } }) })
  };
  assert.deepEqual(await claimWebhookEvent({
    provider: 'test', eventId: 'event-1', rawBody, client: duplicateClient
  }), { claimed: false, duplicate: true });

  const failingClient = {
    from: () => ({ insert: async () => ({ error: { code: 'XX000', message: 'offline' } }) })
  };
  await assert.rejects(
    claimWebhookEvent({ provider: 'test', eventId: 'event-2', rawBody, client: failingClient }),
    /replay store unavailable/
  );
});

test('WooCommerce and GHL signatures fail closed', () => {
  const body = Buffer.from('{"id":42}');
  const wooSecret = 'woo-test-secret';
  const wooSignature = crypto.createHmac('sha256', wooSecret).update(body).digest('base64');
  assert.equal(verifyWooCommerceWebhook(body, wooSignature, wooSecret), true);
  assert.equal(verifyWooCommerceWebhook(body, `${wooSignature}x`, wooSecret), false);

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const ghlSignature = crypto.sign(null, body, privateKey).toString('base64');
  assert.equal(verifyGHLWebhook(
    body,
    ghlSignature,
    publicKey.export({ type: 'spki', format: 'pem' })
  ), true);
  assert.equal(verifyGHLWebhook(body, 'invalid', publicKey), false);
});

test('GHL boundary requires the configured location even for a valid signature', async () => {
  const body = Buffer.from(JSON.stringify({
    type: 'ContactCreate',
    locationId: 'location-a',
    id: 'contact-1'
  }));
  const request = { body, get: () => 'valid-for-test' };
  const options = {
    env: { GHL_LOCATION_ID: 'location-a' },
    claim: async () => ({ duplicate: false }),
    verify: () => true
  };

  const verified = await authenticateGHL(request, options);
  assert.equal(verified.body.locationId, 'location-a');

  await assert.rejects(
    authenticateGHL(request, { ...options, env: {} }),
    /location is not configured/
  );
  await assert.rejects(
    authenticateGHL(request, { ...options, env: { GHL_LOCATION_ID: 'location-b' } }),
    /location mismatch/
  );
});

test('staging Telnyx sends only to the explicit allowlist and owns its callbacks', async () => {
  const calls = [];
  const env = {
    APP_ENVIRONMENT: 'staging',
    APP_URL: 'https://staging.example.com',
    STAGING_ALLOWED_RECIPIENTS: '+15555550100',
    TELNYX_PHONE_NUMBER: '+15555550199',
    TELNYX_MESSAGING_PROFILE_ID: 'profile-test',
    TELNYX_API_KEY: 'test-key'
  };
  const fetchImpl = async (url, options) => {
    calls.push({ url, body: JSON.parse(options.body) });
    return {
      ok: true,
      json: async () => ({ data: { id: 'message-1', to: [{ status: 'queued' }] } })
    };
  };
  await sendSMS('+1 (555) 555-0100', 'Staging test', null, { env, fetchImpl });
  assert.equal(calls[0].body.to, '+15555550100');
  assert.equal(calls[0].body.webhook_url, 'https://staging.example.com/webhook/telnyx');
  assert.equal(calls[0].body.use_profile_webhooks, false);

  await assert.rejects(
    sendSMS('+15555550101', 'Must never send', null, { env, fetchImpl }),
    /restricted to approved test recipients/
  );
  assert.equal(calls.length, 1);
});

test('CORS uses exact origins and never trusts arbitrary Railway subdomains', () => {
  const env = {
    NODE_ENV: 'production',
    APP_URL: 'https://vici-staging.up.railway.app',
    CORS_ALLOWED_ORIGINS: 'https://preview.example.com'
  };
  assert.equal(originAllowed('https://vici-staging.up.railway.app', env), true);
  assert.equal(originAllowed('https://preview.example.com', env), true);
  assert.equal(originAllowed('https://attacker.up.railway.app', env), false);
  assert.equal(originAllowed('https://vici-staging.up.railway.app.attacker.test', env), false);
  assert.equal(originAllowed(undefined, env), true); // native app/provider requests
});

test('staging startup fails closed without safety variables', () => {
  const safe = {
    APP_ENVIRONMENT: 'staging',
    APP_URL: 'https://staging.example.com',
    NODE_ENV: 'production',
    ENABLED_INTEGRATIONS: '',
    SUPABASE_URL: 'https://unit-test.supabase.co',
    SUPABASE_SERVICE_KEY: 'service-test',
    SESSION_SECRET: 's'.repeat(32),
    INBOX_PASSWORD: 'password-long-enough',
    STAGING_ALLOWED_RECIPIENTS: '+15555550100'
  };
  assert.equal(validateRuntimeConfig(safe), true);
  assert.throws(
    () => validateRuntimeConfig({ ...safe, SESSION_SECRET: 'short' }),
    /SESSION_SECRET/
  );
  assert.throws(
    () => validateRuntimeConfig({ ...safe, STAGING_ALLOWED_RECIPIENTS: '' }),
    /STAGING_ALLOWED_RECIPIENTS/
  );
});
