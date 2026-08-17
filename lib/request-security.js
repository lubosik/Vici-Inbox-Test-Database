'use strict';

function allowedOrigins(env = process.env) {
  const values = [env.APP_URL, ...String(env.CORS_ALLOWED_ORIGINS || '').split(',')]
    .map(value => String(value || '').trim())
    .filter(Boolean);
  if (env.NODE_ENV !== 'production') values.push('http://localhost:3000');
  return new Set(values.map(value => {
    try { return new URL(value).origin; } catch { return null; }
  }).filter(Boolean));
}

function originAllowed(origin, env = process.env) {
  if (!origin) return true; // native apps and provider-to-provider requests
  try { return allowedOrigins(env).has(new URL(origin).origin); } catch { return false; }
}

function requireTrustedMutationOrigin(req, res, next) {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return next();
  const origin = req.get('origin');
  const fetchSite = req.get('sec-fetch-site');
  if ((origin && !originAllowed(origin)) || fetchSite === 'cross-site') {
    return res.status(403).json({ error: 'Untrusted request origin' });
  }
  next();
}

module.exports = { allowedOrigins, originAllowed, requireTrustedMutationOrigin };
