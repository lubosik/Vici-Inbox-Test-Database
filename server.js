require('dotenv').config();
const express      = require('express');
const cookieSession = require('cookie-session');
const cors    = require('cors');
const helmet  = require('helmet');
const rateLimit = require('express-rate-limit');
const path    = require('path');
const { verifyConnection }    = require('./db');
const { checkAndSendDeliverySMS, pollForCarrierScans } = require('./routes/webhook-shipstation');
const { processScheduledQueue } = require('./flows/utils');
const { startRecordingRetentionJob } = require('./lib/private-recordings');
const { integrationEnabled, validateRuntimeConfig } = require('./lib/runtime-config');
const { originAllowed, requireTrustedMutationOrigin } = require('./lib/request-security');
require('./push-notify'); // initialises VAPID on startup

const app = express();
app.disable('x-powered-by');

const sseClients = new Set();
function broadcastSSE(event) {
  const data = `data: ${JSON.stringify(event)}\n\n`;
  sseClients.forEach(client => {
    try { client.write(data); } catch { sseClients.delete(client); }
  });
}
require('./lib/broadcaster').setBroadcast(broadcastSSE);

app.use(helmet({ contentSecurityPolicy: false }));

app.use(cors({
  origin: (origin, cb) => {
    cb(null, originAllowed(origin));
  },
  credentials: true
}));

app.set('trust proxy', 1);

function requireEnabledIntegration(name) {
  return (_req, res, next) => {
    if (integrationEnabled(name)) return next();
    return res.status(503).json({ error: 'Integration is disabled' });
  };
}

// Signature verification must see the exact bytes received from each provider.
const rawWebhook = express.raw({ type: 'application/json', limit: '1mb' });
app.use('/webhook/telnyx',               requireEnabledIntegration('telnyx'), rawWebhook);
app.use('/webhook/woocommerce',          requireEnabledIntegration('woocommerce'), rawWebhook);
app.use('/webhook/woocommerce-customer', requireEnabledIntegration('woocommerce'), rawWebhook);
app.use('/webhook/ghl',                  requireEnabledIntegration('ghl'), rawWebhook);
app.use('/webhook/send',                 requireEnabledIntegration('ghl-bridge'), rawWebhook);
app.use('/webhooks/voice',               requireEnabledIntegration('voice'), rawWebhook);

// Parsed JSON for the rest
app.use('/webhook/shipstation', requireEnabledIntegration('shipstation'), express.json());
// Image uploads arrive as base64 JSON — needs a higher limit than the default 100kb
app.use('/api/upload', express.json({ limit: '8mb' }));
app.use(express.json({ limit: '1mb' }));

// Cookie-session: signed client-side cookie — survives Railway restarts/redeploys.
// Session only stores { authenticated: true } so cookie stays tiny (<100 bytes).
app.use(cookieSession({
  name:   'vici_sess',
  secret: process.env.SESSION_SECRET,
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  // Interim shared-password control. Phase 3 replaces this with individual,
  // revocable accounts and device/session inventory.
  maxAge: 7 * 24 * 60 * 60 * 1000
}));

function requireAuth(req, res, next) {
  if (req.session?.authenticated) return next();
  return res.status(401).json({ error: 'Unauthorised' });
}

const sendLimiter = rateLimit({
  windowMs: 60000,
  max: 20,
  message: { error: 'Too many messages, slow down' }
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again later.' }
});

// ── Webhooks (no auth) ────────────────────────────────────────────────────
app.use('/webhook', require('./routes/webhook')(broadcastSSE));
app.use('/webhook', require('./routes/webhook-ghl')(broadcastSSE));
app.use('/webhook', require('./routes/webhook-send')(broadcastSSE));
app.use('/webhook', require('./routes/webhook-woocommerce')(broadcastSSE));
app.use('/webhook', require('./routes/webhook-shipstation')(broadcastSSE));

// ── Auth ──────────────────────────────────────────────────────────────────
app.use('/auth', requireTrustedMutationOrigin);
app.use('/auth/login', authLimiter);
app.use('/auth', require('./routes/auth'));

// ── Admin (backfill endpoints, protected by INBOX_PASSWORD) ──────────────
app.use('/admin', requireTrustedMutationOrigin, require('./routes/admin')());

// ── Authenticated API routes ──────────────────────────────────────────────
app.use('/api', requireTrustedMutationOrigin);
app.use('/api/sse',           requireAuth, require('./routes/sse')(sseClients));
app.use('/api/send',          requireAuth, requireEnabledIntegration('telnyx'), sendLimiter, require('./routes/send')(broadcastSSE));
app.use('/api/upload',        requireAuth, require('./routes/upload'));
app.use('/api/react',         requireAuth, requireEnabledIntegration('telnyx'), sendLimiter, require('./routes/react')(broadcastSSE));
app.use('/api/conversations', requireAuth, require('./routes/conversations'));
app.use('/api/intelligence',  requireAuth, requireEnabledIntegration('openrouter'), require('./routes/intelligence'));
app.use('/api/sync',          requireAuth, require('./routes/sync'));
app.use('/api/contacts',      requireAuth, require('./routes/contacts'));
app.use('/api/catchup',       requireAuth, require('./routes/catchup'));
app.use('/api/push',          requireAuth, require('./routes/push')());
app.use('/api/mobile-push',   requireAuth, require('./routes/mobile-push')());
app.use('/api/activity',      requireAuth, require('./routes/activity'));
app.use('/api/voice',         requireAuth, requireEnabledIntegration('voice'), require('./routes/voice'));

// Voice webhooks (public — Telnyx calls this directly)
app.use('/webhooks/voice', require('./routes/voice-webhook'));

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    environment: process.env.APP_ENVIRONMENT,
    uptime: Math.floor(process.uptime()),
    ts: new Date().toISOString()
  });
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('/{*splat}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Background jobs ────────────────────────────────────────────────────────

// Every 5 minutes — process scheduled SMS queue (failed/hold sequences + delivery check-ins)
function startScheduledQueue() {
  const FIVE_MINUTES = 5 * 60 * 1000;
  // Run once 15s after boot to catch anything queued before restart
  setTimeout(async () => {
    try { await processScheduledQueue(); }
    catch (err) { console.error('[QUEUE] Startup run error:', err.message); }
  }, 15 * 1000);

  setInterval(async () => {
    try { await processScheduledQueue(); }
    catch (err) { console.error('[QUEUE] Cron error:', err.message); }
  }, FIVE_MINUTES);
}

// Every 30 minutes — poll ShipStation for carrier scans
// Sends shipped SMS only when shipmentStatus === 'shipped' (not on label creation)
function startShipmentPoll() {
  const THIRTY_MINUTES = 30 * 60 * 1000;
  setTimeout(async () => {
    try { await pollForCarrierScans(); }
    catch (err) { console.error('[POLL] Startup poll error:', err.message); }
  }, 10 * 1000);

  setInterval(async () => {
    try { await pollForCarrierScans(); }
    catch (err) { console.error('[POLL] Poll cron error:', err.message); }
  }, THIRTY_MINUTES);
}

// Every 6 hours — delivery review SMS for legacy orders (5 days after shipping)
function startDeliveryCheck() {
  const SIX_HOURS = 6 * 60 * 60 * 1000;
  setInterval(async () => {
    try {
      const sent = await checkAndSendDeliverySMS();
      if (sent > 0) console.log(`[DELIVERY] Sent ${sent} review SMS`);
    } catch (err) {
      console.error('[DELIVERY] Cron error:', err.message);
    }
  }, SIX_HOURS);
}

async function startServer() {
  validateRuntimeConfig();
  const PORT = process.env.PORT || 3000;
  const server = app.listen(PORT, async () => {
  await verifyConnection();
  if (integrationEnabled('automations')) startScheduledQueue();
  if (integrationEnabled('shipstation')) {
    startShipmentPoll();
    startDeliveryCheck();
  }
  startRecordingRetentionJob();
    console.log(`Vici Inbox ${process.env.APP_ENVIRONMENT} running on port ${PORT}`);
    console.log(`Integrations: ${process.env.ENABLED_INTEGRATIONS || 'none'}`);
  });
  return server;
}

if (require.main === module) {
  startServer().catch(error => {
    console.error('[STARTUP] Refusing unsafe startup:', error.message);
    process.exit(1);
  });
}

module.exports = { app, broadcastSSE, startServer };
