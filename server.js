/**
 * SMMARIA NOTIFICATIONS — Main Server
 *
 * Standalone Web Push Notification backend for SMMARIA PANEL.
 * Runs on Railway using process.env.PORT.
 * Completely independent from the existing SMMARIA backend.
 *
 * NEVER exposes:
 *   FIREBASE_SERVICE_ACCOUNT
 *   VAPID_PRIVATE_KEY
 *   ADMIN_KEY
 *   SMMARIA_JWT_SECRET
 */

const express = require('express');
const cors = require('cors');
const { initFirebase, isAvailable } = require('./firebase');
const { configureVapid } = require('./push');
const routes = require('./routes');

const app = express();
const PORT = process.env.PORT || 3000;

// ── CORS ─────────────────────────────────────────────────────────
// Configure ALLOWED_ORIGINS in Railway:
// https://smmaria.site,https://notification-admin.smmaria.site
const allowedOrigins = process.env.ALLOWED_ORIGINS ?
 process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim()) :
 true; // true = allow all (development only)

app.use(cors({
 origin: allowedOrigins === true ? true : function(origin, callback) {
  if (!origin || allowedOrigins.includes(origin)) {
   callback(null, true);
  } else {
   callback(new Error('CORS not allowed'));
  }
 },
 credentials: true,
 methods: ['GET', 'POST', 'OPTIONS']
}));

// ── Body Parser ──────────────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));

// ── Request Logger (no secrets) ──────────────────────────────────
app.use((req, res, next) => {
 console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
 next();
});

// ── Initialize Firebase & VAPID on startup ──────────────────────
initFirebase();
configureVapid();

// ── Mount Routes ──────────────────────────────────────────────────
app.use(routes);

// ── Health Check (also at /api/health via routes) ────────────────
app.get('/', (req, res) => {
 res.json({
  success: true,
  service: 'SMMARIA Notification Service',
  status: 'online',
  firebase: isAvailable() ? 'connected' : 'disconnected',
  endpoints: {
   health: 'GET /api/health',
   config: 'GET /api/config',
   subscribe: 'POST /api/subscribe',
   unsubscribe: 'POST /api/unsubscribe',
   subscriptionStatus: 'GET /api/subscription/status',
   analyticsClick: 'POST /api/analytics/click',
   adminStats: 'GET /api/admin/stats',
   adminUsers: 'GET /api/admin/users',
   adminNotifications: 'GET /api/admin/notifications',
   adminSend: 'POST /api/admin/send',
   adminSendUser: 'POST /api/admin/send-user',
   adminAnalytics: 'GET /api/admin/analytics/:notificationId'
  }
 });
});

// ── 404 Handler ──────────────────────────────────────────────────
app.use((req, res) => {
 res.status(404).json({
  success: false,
  message: 'Endpoint not found'
 });
});

// ── Global Error Handler ────────────────────────────────────────
// NEVER return stack traces to the browser
app.use((err, req, res, next) => {
 console.error('[error]', err.message);
 if (err.message === 'CORS not allowed') {
  return res.status(403).json({
   success: false,
   message: 'Origin not allowed'
  });
 }
 res.status(500).json({
  success: false,
  message: 'Internal server error'
 });
});

// ── Start Server ────────────────────────────────────────────────
app.listen(PORT, () => {
 console.log('═══════════════════════════════════════════════');
 console.log('  SMMARIA Notification Service');
 console.log('  Port:', PORT);
 console.log('  Firebase:', isAvailable() ? 'Connected' : 'Disconnected');
 console.log('  VAPID:', process.env.VAPID_PUBLIC_KEY ? 'Configured' : 'Not set');
 console.log('  JWT:', process.env.SMMARIA_JWT_SECRET ? 'Configured' : (process.env.DEV_MODE === 'true' ? 'DEV MODE' : 'Not set'));
 console.log('  Admin:', process.env.ADMIN_KEY ? 'Protected' : 'Unprotected');
 console.log('═══════════════════════════════════════════════');
});