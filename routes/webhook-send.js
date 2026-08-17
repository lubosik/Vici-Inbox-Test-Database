/**
 * POST /webhook/send
 * Called by GHL custom webhook action to send an outbound SMS.
 * Mirrors the old bridge's /send endpoint format exactly.
 * Auth: Authorization: Bearer <GHL_BRIDGE_SECRET> plus Idempotency-Key.
 * Secrets in query strings or request bodies are intentionally rejected.
 */

const { supabase } = require('../db');
const { sendSMS } = require('../telnyx');
const { normaliseTelnyxStatus } = require('../lib/message-status');
const { authenticateGHLBridge, rejectWebhook } = require('../lib/webhook-boundary');

function extractPayload(body = {}) {
  const c = body.customData || body.custom_data || body.data?.customData || {};
  return {
    to:        body.to        || c.to        || body.phone       || body.contact?.phone,
    message:   body.message   || c.message   || body.text        || c.text,
    contactId: body.contactId || body.contactID || c.contactId   || c.contactID || body.contact?.id,
    name:      body.name      || c.name      || body.contact?.name ||
               [body.contact?.firstName, body.contact?.lastName].filter(Boolean).join(' ') || null
  };
}

function isValidPhone(phone) {
  if (!phone) return false;
  const digits = String(phone).replace(/\D/g, '');
  return digits.length >= 10 && digits.length <= 15;
}

module.exports = (broadcastSSE) => {
  const router = require('express').Router();

  router.post('/send', async (req, res) => {
    let verified;
    try {
      verified = await authenticateGHLBridge(req);
    } catch (error) {
      return rejectWebhook(res, error, 'GHL bridge');
    }
    if (verified.duplicate) return res.json({ success: true, duplicate: true });

    const { to, message, contactId, name } = extractPayload(verified.body);

    if (!to || !message) {
      console.warn('GHL send webhook missing fields. Body keys:', Object.keys(req.body || {}));
      return res.status(400).json({ success: false, error: 'Missing required fields: to, message' });
    }

    if (!isValidPhone(to)) {
      return res.status(400).json({ success: false, error: 'Invalid phone number' });
    }

    try {
      // Send via Telnyx
      const { messageId, status: providerStatus } = await sendSMS(to, message);

      // Insert before secondary contact work so an immediate Telnyx delivery
      // callback always has a row to update.
      await supabase.from('sms_messages').insert({
        telnyx_message_id: messageId,
        contact_phone: to,
        direction: 'outbound',
        body: message,
        status: normaliseTelnyxStatus(providerStatus),
        ghl_contact_id: contactId || null
      });

      // Ensure contact exists in Supabase
      await supabase.from('sms_contacts').upsert({
        phone: to,
        name: name || null,
        ghl_contact_id: contactId || null,
        last_seen: new Date().toISOString()
      }, { onConflict: 'phone' });

      // Push to inbox live
      broadcastSSE({ type: 'new_message', phone: to, body: message, direction: 'outbound' });

      console.log(`GHL automation SMS sent to ...${String(to).replace(/\D/g, '').slice(-4)}`);
      return res.json({ success: true, messageId, status: 'accepted' });

    } catch (err) {
      console.error('GHL send webhook error:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }
  });

  return router;
};
