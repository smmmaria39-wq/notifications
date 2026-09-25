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
const { configureVapid, processScheduledNotifications } = require('./push');
const routes = require('./routes');

const app = express();
const PORT = process.env.PORT || 3000;

// ── CORS ─────────────────────────────────────────────────────────
// Configure ALLOWED_ORIGINS in Railway:
// https://smmaria.site,https://notification-admin.smmaria.site
const allowedOrigins = process.env.ALLOWED_ORIGINS ?
 process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim().replace(/\/$/, '')) :
 true; // true = allow all (development only)

app.use(cors({
 origin: allowedOrigins === true ? true : function(origin, callback) {
  var cleanOrigin = origin ? origin.replace(/\/$/, '') : origin;
  if (!origin || allowedOrigins.indexOf(cleanOrigin) !== -1) {
   callback(null, true);
  } else {
   callback(new Error('CORS not allowed'));
  }
 },
 credentials: true,
 methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
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
   inAppSubscribe: 'POST /api/in-app/subscribe',
   inAppNotifications: 'GET /api/in-app/notifications',
   inAppDismiss: 'POST /api/in-app/dismiss',
   inAppStatus: 'GET /api/in-app/status',
   adminStats: 'GET /api/admin/stats',
   adminUsers: 'GET /api/admin/users',
   adminNotifications: 'GET /api/admin/notifications',
   adminSend: 'POST /api/admin/send',
   adminSendUser: 'POST /api/admin/send-user',
   adminAnalytics: 'GET /api/admin/analytics/:notificationId',
   adminResend: 'POST /api/admin/resend/:notificationId',
   adminDuplicate: 'GET /api/admin/duplicate/:notificationId',
   adminDelete: 'DELETE /api/admin/notifications/:notificationId',
   adminSendTest: 'POST /api/admin/send-test',
   adminTestSubscribe: 'POST /api/admin/test-subscribe',
   adminTestStatus: 'GET /api/admin/test-subscription',
   adminTemplates: 'GET/POST /api/admin/templates',
   adminTemplateCRUD: 'PUT/DELETE /api/admin/templates/:id',
   adminDrafts: 'GET/POST /api/admin/drafts',
   adminDraftCRUD: 'PUT/DELETE /api/admin/drafts/:id',
   adminDraftSend: 'POST /api/admin/drafts/:id/send',
   adminScheduled: 'GET/POST /api/admin/scheduled',
   adminScheduledCRUD: 'PUT /api/admin/scheduled/:id',
   adminScheduledCancel: 'POST /api/admin/scheduled/:id/cancel',
   adminScheduledSend: 'POST /api/admin/scheduled/:id/send',
   adminAuditLogs: 'GET /api/admin/audit-logs'
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

// ═══════════════════════════════════════════════════════════════
//  SCHEDULED NOTIFICATION PROCESSING
//  On startup: check for pending scheduled notifications that
//  were due while the server was offline (Railway restart recovery).
//  Then check every 60 seconds for newly-due scheduled notifications.
//  Uses atomic status transition: scheduled → sending → sent
//  to prevent duplicate sends.
// ═══════════════════════════════════════════════════════════════

// Wait 5 seconds for Firebase to be fully ready, then process
// any scheduled notifications that were due while the server was down
setTimeout(async function () {
 console.log('[server] Checking for pending scheduled notifications (startup recovery)...');
 try {
  await processScheduledNotifications();
  console.log('[server] Startup scheduled check complete');
 } catch (e) {
  console.error('[server] Startup scheduled check failed:', e.message);
 }
}, 5000);

// Check every 60 seconds for scheduled notifications that are now due
setInterval(async function () {
 try {
  await processScheduledNotifications();
 } catch (e) {
  // Silent fail — don't crash the server
  console.error('[server] Scheduled check error:', e.message);
 }
}, 60000);

// ── Start Server ────────────────────────────────────────────────
app.listen(PORT, () => {
 console.log('═══════════════════════════════════════════════');
 console.log('  SMMARIA Notification Service');
 console.log('  Port:', PORT);
 console.log('  Firebase:', isAvailable() ? 'Connected' : 'Disconnected');
 console.log('  VAPID:', process.env.VAPID_PUBLIC_KEY ? 'Configured' : 'Not set');
 console.log('  JWT:', process.env.SMMARIA_JWT_SECRET ? 'Configured' : (process.env.DEV_MODE === 'true' ? 'DEV MODE' : 'Not set'));
 console.log('  Admin:', process.env.ADMIN_KEY ? 'Protected' : 'Unprotected');
 console.log('  Scheduled processing: Active (60s interval)');
 console.log('═══════════════════════════════════════════════');
});
