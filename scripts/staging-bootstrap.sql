-- Vici Inbox staging database bootstrap.
--
-- This creates structure only. It never copies production customers, messages,
-- recordings, orders, device tokens, or credentials. Safe to run on the new,
-- empty staging Supabase project. Re-running is idempotent.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS sms_contacts (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  phone text UNIQUE NOT NULL,
  name text,
  ghl_contact_id text,
  total_messages integer NOT NULL DEFAULT 0,
  unread_count integer NOT NULL DEFAULT 0,
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz NOT NULL DEFAULT now(),
  woo_customer_id integer,
  email text,
  city text,
  state text,
  country text,
  first_name text,
  last_name text,
  notes text,
  source text NOT NULL DEFAULT 'sms',
  created_at timestamptz NOT NULL DEFAULT now(),
  avatar_url text,
  opted_out boolean NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS sms_messages (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  telnyx_message_id text UNIQUE,
  contact_phone text NOT NULL,
  direction text NOT NULL CHECK (direction IN ('inbound', 'outbound')),
  body text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'delivered',
  ghl_contact_id text,
  ghl_conversation_id text,
  ghl_message_id text,
  ai_processed boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  media_urls jsonb,
  reply_to_message_id bigint,
  reactions jsonb
);

CREATE TABLE IF NOT EXISTS sms_orders (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  contact_phone text,
  woo_order_id integer UNIQUE,
  shipstation_order_id text,
  status text NOT NULL DEFAULT 'pending',
  items jsonb,
  total numeric NOT NULL DEFAULT 0,
  tracking_number text,
  carrier text,
  shipped_at timestamptz,
  delivered_at timestamptz,
  order_sms_sent boolean NOT NULL DEFAULT false,
  shipped_sms_sent boolean NOT NULL DEFAULT false,
  delivery_sms_sent boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sms_scheduled (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  order_id text,
  phone text NOT NULL,
  flow_type text NOT NULL,
  message_body text NOT NULL,
  send_at timestamptz NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  attempts integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sms_sent_log (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  order_id text NOT NULL,
  flow_type text NOT NULL,
  phone text NOT NULL,
  message_body text,
  telnyx_message_id text,
  sent_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (order_id, flow_type)
);

CREATE TABLE IF NOT EXISTS sms_customer_profiles (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  contact_phone text UNIQUE NOT NULL,
  ghl_contact_id text,
  inferred_interests jsonb,
  order_signals jsonb,
  restock_interests jsonb,
  campaign_recommendations jsonb,
  sentiment text NOT NULL DEFAULT 'neutral',
  last_analysed timestamptz,
  raw_summary text,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sms_campaign_suggestions (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  contact_phone text NOT NULL,
  suggestion_type text NOT NULL,
  suggestion_text text,
  suggested_message text,
  status text NOT NULL DEFAULT 'pending',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS push_subscriptions (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  endpoint text UNIQUE NOT NULL,
  subscription jsonb NOT NULL,
  user_agent text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ios_push_devices (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  device_token text UNIQUE NOT NULL,
  installation_id text,
  environment text NOT NULL DEFAULT 'production'
    CHECK (environment IN ('sandbox', 'production')),
  bundle_id text NOT NULL DEFAULT 'com.vicipeptides.inbox.staging',
  enabled boolean NOT NULL DEFAULT true,
  user_agent text,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS call_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  call_control_id text UNIQUE,
  call_leg_id text,
  call_session_id text,
  direction text CHECK (direction IN ('inbound', 'outbound')),
  contact_phone text NOT NULL,
  from_number text,
  to_number text,
  status text NOT NULL DEFAULT 'initiated',
  duration_seconds integer NOT NULL DEFAULT 0,
  recording_id text,
  recording_url_mp3 text,
  recording_url_wav text,
  recording_storage_path text,
  recording_content_type text,
  recording_archived_at timestamptz,
  recording_expires_at timestamptz,
  recording_deleted_at timestamptz,
  started_at timestamptz NOT NULL DEFAULT now(),
  answered_at timestamptz,
  ended_at timestamptz,
  seen_at timestamptz
);

CREATE TABLE IF NOT EXISTS shipstation_tracking (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  woo_order_id text,
  shipstation_shipment_id text UNIQUE NOT NULL,
  shipstation_order_id text,
  tracking_number text,
  carrier text,
  customer_phone text,
  customer_name text,
  shipment_status text NOT NULL DEFAULT 'label_created',
  voided boolean NOT NULL DEFAULT false,
  shipped_sms_sent boolean NOT NULL DEFAULT false,
  delivery_sms_sent boolean NOT NULL DEFAULT false,
  label_created_at timestamptz NOT NULL DEFAULT now(),
  shipped_at timestamptz,
  delivered_at timestamptz,
  last_polled timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS webhook_events (
  provider text NOT NULL,
  event_id text NOT NULL,
  payload_sha256 text NOT NULL CHECK (payload_sha256 ~ '^[a-f0-9]{64}$'),
  received_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (provider, event_id)
);

COMMENT ON TABLE webhook_events IS
  'Provider webhook replay claims. Contains identifiers and hashes, never payload bodies.';

CREATE INDEX IF NOT EXISTS idx_sms_messages_phone_created
  ON sms_messages(contact_phone, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sms_contacts_last_seen
  ON sms_contacts(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_sms_contacts_opted_out
  ON sms_contacts(opted_out) WHERE opted_out = true;
CREATE INDEX IF NOT EXISTS idx_sms_orders_phone_created
  ON sms_orders(contact_phone, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sms_scheduled_due
  ON sms_scheduled(status, send_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_ios_push_devices_enabled
  ON ios_push_devices(enabled, environment, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_call_logs_started
  ON call_logs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_call_logs_phone
  ON call_logs(contact_phone);
CREATE INDEX IF NOT EXISTS call_logs_unseen_missed_idx
  ON call_logs(started_at DESC)
  WHERE direction = 'inbound' AND status = 'missed' AND seen_at IS NULL;
CREATE INDEX IF NOT EXISTS call_logs_recording_expiry_idx
  ON call_logs(recording_expires_at)
  WHERE recording_expires_at IS NOT NULL AND recording_deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_ss_pending_poll
  ON shipstation_tracking(shipped_sms_sent, voided)
  WHERE shipped_sms_sent = false AND voided = false;
CREATE INDEX IF NOT EXISTS webhook_events_received_idx
  ON webhook_events(received_at);

CREATE OR REPLACE FUNCTION increment_contact_messages(p_phone text)
RETURNS void LANGUAGE sql AS $$
  UPDATE sms_contacts
  SET total_messages = COALESCE(total_messages, 0) + 1
  WHERE phone = p_phone;
$$;

CREATE OR REPLACE FUNCTION increment_unread(p_phone text)
RETURNS void LANGUAGE sql AS $$
  UPDATE sms_contacts
  SET unread_count = COALESCE(unread_count, 0) + 1
  WHERE phone = p_phone;
$$;

-- The native and web clients use the Railway API, never Supabase directly.
-- With no anon/authenticated policies, RLS prevents the publishable key from
-- reading private application rows; the backend service role still functions.
ALTER TABLE sms_contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE sms_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE sms_orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE sms_scheduled ENABLE ROW LEVEL SECURITY;
ALTER TABLE sms_sent_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE sms_customer_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE sms_campaign_suggestions ENABLE ROW LEVEL SECURITY;
ALTER TABLE push_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ios_push_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE call_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE shipstation_tracking ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_events ENABLE ROW LEVEL SECURITY;

-- Explicitly keep browser-facing roles away from all private application data.
-- The Railway backend uses the service role and is not affected by these
-- revocations.
REVOKE ALL ON TABLE sms_contacts FROM anon, authenticated;
REVOKE ALL ON TABLE sms_messages FROM anon, authenticated;
REVOKE ALL ON TABLE sms_orders FROM anon, authenticated;
REVOKE ALL ON TABLE sms_scheduled FROM anon, authenticated;
REVOKE ALL ON TABLE sms_sent_log FROM anon, authenticated;
REVOKE ALL ON TABLE sms_customer_profiles FROM anon, authenticated;
REVOKE ALL ON TABLE sms_campaign_suggestions FROM anon, authenticated;
REVOKE ALL ON TABLE push_subscriptions FROM anon, authenticated;
REVOKE ALL ON TABLE ios_push_devices FROM anon, authenticated;
REVOKE ALL ON TABLE call_logs FROM anon, authenticated;
REVOKE ALL ON TABLE shipstation_tracking FROM anon, authenticated;
REVOKE ALL ON TABLE webhook_events FROM anon, authenticated;

INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES
  ('mms-media', 'mms-media', true, 1048576,
    ARRAY['image/jpeg', 'image/png', 'image/gif', 'image/webp']),
  ('call-recordings', 'call-recordings', false, 104857600,
    ARRAY['audio/mpeg', 'audio/mp3', 'audio/wav', 'audio/x-wav'])
ON CONFLICT (id) DO UPDATE SET
  public = EXCLUDED.public,
  file_size_limit = EXCLUDED.file_size_limit,
  allowed_mime_types = EXCLUDED.allowed_mime_types;
