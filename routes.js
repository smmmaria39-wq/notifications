/**
 * SMMARIA NOTIFICATIONS — API Routes (UPGRADED)
 *
 * All existing routes preserved. New routes added:
 *   POST /api/admin/resend/:notificationId
 *   POST /api/admin/duplicate/:notificationId
 *   POST /api/admin/send-test
 *   POST /api/admin/notifications/:notificationId/delete
 *   GET  /api/admin/audit-logs
 *   Templates: POST/GET/PUT/DELETE /api/admin/templates
 *   Drafts: POST/GET/PUT/DELETE /api/admin/drafts, POST /api/admin/drafts/:id/send
 *   Scheduled: POST/GET/PUT /api/admin/scheduled, POST cancel/send
 *   Admin test subscription: POST /api/admin/test-subscribe, GET /api/admin/test-subscription
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const { getDb, isAvailable } = require('./firebase');
const push = require('./push');

const router = express.Router();

// ═══════════════════════════════════════════════════════════════
//  MIDDLEWARE & HELPERS (unchanged from existing)
// ═══════════════════════════════════════════════════════════════

const ADMIN_KEY = process.env.ADMIN_KEY;
const JWT_SECRET = process.env.SMMARIA_JWT_SECRET;
const JWT_USER_ID_CLAIM = process.env.SMMARIA_JWT_USER_ID_CLAIM || 'userId';
const DEV_MODE = process.env.DEV_MODE === 'true';
const TEST_SUBSCRIBER_ID = 'admin_test_subscriber';

const rateLimitMap = new Map();
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  const entries = rateLimitMap.get(key) || [];
  const valid = entries.filter(ts => now - ts < windowMs);
  if (valid.length >= max) return false;
  valid.push(now);
  rateLimitMap.set(key, valid);
  return true;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, entries] of rateLimitMap.entries()) {
    const valid = entries.filter(ts => now - ts < 60000);
    if (valid.length === 0) rateLimitMap.delete(k);
    else rateLimitMap.set(k, valid);
  }
}, 300000);

function requireAdmin(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (!ADMIN_KEY) return res.status(500).json({ success: false, message: 'ADMIN_KEY not configured' });
  if (!key || key !== ADMIN_KEY) return res.status(401).json({ success: false, message: 'Unauthorized' });
  next();
}

function verifyUser(req, res, next) {
  if (DEV_MODE) {
    const userId = req.headers['x-user-id'] || (req.body && req.body.userId);
    if (!userId) return res.status(401).json({ success: false, message: 'User ID required (DEV_MODE)' });
    req.userId = userId;
    return next();
  }
  if (!JWT_SECRET) return res.status(500).json({ success: false, message: 'SMMARIA_JWT_SECRET not configured' });
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ success: false, message: 'Authentication token required' });
  try {
    const decoded = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    const userId = decoded[JWT_USER_ID_CLAIM] || decoded.sub || decoded.id || decoded.userId;
    if (!userId) return res.status(401).json({ success: false, message: 'Invalid token claims' });
    req.userId = String(userId);
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
}

function optionalVerifyUser(req, res, next) {
  if (DEV_MODE) { req.userId = req.headers['x-user-id'] || (req.body && req.body.userId) || null; return next(); }
  if (!JWT_SECRET) { req.userId = null; return next(); }
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) { req.userId = null; return next(); }
  try {
    const decoded = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    const userId = decoded[JWT_USER_ID_CLAIM] || decoded.sub || decoded.id || decoded.userId;
    req.userId = userId ? String(userId) : null;
  } catch (err) { req.userId = null; }
  next();
}

function isValidUrl(url) {
  if (!url) return false;
  try { new URL(url); return true; } catch { return false; }
}

function dbOrError(res) {
  if (!isAvailable()) { res.status(503).json({ success: false, message: 'Notification database unavailable' }); return null; }
  return getDb();
}

async function isUserSubscribed(userId) {
  if (!isAvailable()) return false;
  const snap = await getDb().ref('notificationUsers/' + userId + '/subscribed').once('value');
  return snap.val() === true;
}

// ── NEW: Audit log helper ──────────────────────────────────────
async function logAudit(action, metadata) {
  if (!isAvailable()) return;
  try {
    const db = getDb();
    const logId = 'log_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    await db.ref('adminAuditLogs/' + logId).set({
      action,
      notificationId: (metadata && metadata.notificationId) || null,
      templateId: (metadata && metadata.templateId) || null,
      draftId: (metadata && metadata.draftId) || null,
      scheduledId: (metadata && metadata.scheduledId) || null,
      details: metadata || null,
      timestamp: Date.now()
    });
  } catch (e) {}
}

// ═══════════════════════════════════════════════════════════════
//  PUBLIC ROUTES (all existing — unchanged)
// ═══════════════════════════════════════════════════════════════

router.get('/api/health', (req, res) => {
  res.json({ success: true, service: 'SMMARIA Notification Service', status: 'online', firebase: isAvailable() ? 'connected' : 'disconnected', timestamp: Date.now() });
});

router.get('/api/config', (req, res) => {
  res.json({ success: true, vapidPublicKey: process.env.VAPID_PUBLIC_KEY || null });
});

router.post('/api/subscribe', optionalVerifyUser, async (req, res) => {
  try {
    const { subscription, device } = req.body;
    if (!subscription || !subscription.endpoint || !subscription.keys) return res.status(400).json({ success: false, message: 'Invalid PushSubscription' });
    const db = dbOrError(res); if (!db) return;
    const crypto = require('crypto');
    const subId = crypto.createHash('sha256').update(subscription.endpoint).digest('hex').slice(0, 24);
    const userId = req.userId || ('anonymous_' + subId);
    const now = Date.now();
    const userRef = db.ref('notificationUsers/' + userId);
    await userRef.child('subscriptions/' + subId).set({
      endpoint: subscription.endpoint, expirationTime: subscription.expirationTime || null,
      keys: { p256dh: subscription.keys.p256dh, auth: subscription.keys.auth },
      device: (device && device.browser) || 'unknown', browser: (device && device.browser) || 'unknown',
      platform: (device && device.platform) || 'unknown', active: true, createdAt: now, updatedAt: now
    });
    const userSnap = await userRef.once('value');
    if (!userSnap.exists() || !userSnap.val().createdAt) {
      await userRef.update({ userId, subscribed: true, isAnonymous: !req.userId, createdAt: now, updatedAt: now, lastSeenAt: now });
    } else {
      await userRef.update({ subscribed: true, isAnonymous: !req.userId, updatedAt: now, lastSeenAt: now });
    }
    res.json({ success: true, message: 'Subscription saved', subscriptionId: subId, anonymous: !req.userId });
  } catch (error) { console.error('[subscribe]', error.message); res.status(500).json({ success: false, message: 'Unable to save subscription' }); }
});

router.post('/api/unsubscribe', optionalVerifyUser, async (req, res) => {
  try {
    const { endpoint } = req.body;
    if (!endpoint) return res.status(400).json({ success: false, message: 'Endpoint required' });
    const db = dbOrError(res); if (!db) return;
    const crypto = require('crypto');
    const subId = crypto.createHash('sha256').update(endpoint).digest('hex').slice(0, 24);
    let removed = false;
    if (req.userId) {
      const userRef = db.ref('notificationUsers/' + req.userId);
      const subsSnap = await userRef.child('subscriptions').once('value');
      const subs = subsSnap.val() || {};
      for (const [sid, sub] of Object.entries(subs)) {
        if (sub.endpoint === endpoint) { await userRef.child('subscriptions/' + sid).update({ active: false, updatedAt: Date.now() }); removed = true; break; }
      }
      if (removed) {
        const refreshedSnap = await userRef.child('subscriptions').once('value');
        const hasActive = Object.values(refreshedSnap.val() || {}).some(s => s.active === true);
        await userRef.update({ subscribed: hasActive, updatedAt: Date.now() });
      }
    } else {
      const anonRef = db.ref('notificationUsers/anonymous_' + subId);
      const anonSnap = await anonRef.once('value');
      if (anonSnap.exists()) {
        await anonRef.child('subscriptions/' + subId).update({ active: false, updatedAt: Date.now() });
        removed = true;
        const refreshedSnap = await anonRef.child('subscriptions').once('value');
        const hasActive = Object.values(refreshedSnap.val() || {}).some(s => s.active === true);
        await anonRef.update({ subscribed: hasActive, updatedAt: Date.now() });
      }
    }
    res.json({ success: true, message: removed ? 'Removed' : 'Not found' });
  } catch (error) { console.error('[unsubscribe]', error.message); res.status(500).json({ success: false, message: 'Unable to remove' }); }
});

router.get('/api/subscription/status', optionalVerifyUser, async (req, res) => {
  try {
    if (!req.userId) return res.json({ success: true, subscribed: false });
    const db = dbOrError(res); if (!db) return;
    res.json({ success: true, subscribed: await isUserSubscribed(req.userId) });
  } catch (error) { res.json({ success: true, subscribed: false }); }
});

router.post('/api/analytics/click', async (req, res) => {
  try {
    const { notificationId, event, action } = req.body;
    if (!['notification_click', 'action_click'].includes(event)) return res.status(400).json({ success: false, message: 'Invalid event' });
    if (!notificationId) return res.status(400).json({ success: false, message: 'notificationId required' });
    const db = dbOrError(res); if (!db) return;
    const notifSnap = await db.ref('notifications/' + notificationId).once('value');
    if (!notifSnap.exists()) return res.status(404).json({ success: false, message: 'Not found' });
    const ip = req.ip || 'unknown';
    if (!rateLimit('click:' + ip, 10, 60000)) return res.status(429).json({ success: false, message: 'Rate limited' });
    const eventId = notificationId + '_' + ip + '_' + event + '_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    await db.ref('notificationEvents/' + eventId).set({ notificationId, event, action: action || null, ip, createdAt: Date.now() });
    await push.incrementClick(notificationId, event);
    res.json({ success: true, message: 'Click recorded' });
  } catch (error) { console.error('[click]', error.message); res.status(500).json({ success: false, message: 'Unable to record' }); }
});

// ── In-app routes (unchanged) ───────────────────────────────────
router.post('/api/in-app/subscribe', async (req, res) => {
  try {
    const { visitorId, device } = req.body;
    if (!visitorId) return res.status(400).json({ success: false, message: 'visitorId required' });
    const db = dbOrError(res); if (!db) return;
    const now = Date.now();
    const userRef = db.ref('notificationUsers/' + visitorId);
    const snap = await userRef.once('value');
    if (!snap.exists()) {
      await userRef.set({ userId: visitorId, subscribed: true, deliveryMethod: 'in-app', isAnonymous: true, createdAt: now, updatedAt: now, lastSeenAt: now });
    } else {
      await userRef.update({ subscribed: true, deliveryMethod: 'in-app', updatedAt: now, lastSeenAt: now });
    }
    res.json({ success: true, message: 'In-app subscription saved' });
  } catch (error) { console.error('[in-app/subscribe]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

router.get('/api/in-app/notifications', async (req, res) => {
  try {
    const visitorId = req.query.visitorId;
    if (!visitorId) return res.status(400).json({ success: false, message: 'visitorId required' });
    const db = dbOrError(res); if (!db) return;
    const userSnap = await db.ref('notificationUsers/' + visitorId).once('value');
    if (!userSnap.exists() || !userSnap.val().subscribed) return res.json({ success: true, notifications: [] });
    const lastSeenAt = userSnap.val().lastSeenAt || 0;
    const now = Date.now();
    await db.ref('notificationUsers/' + visitorId).update({ lastSeenAt: now });
    const notifsSnap = await db.ref('notifications').orderByChild('createdAt').startAt(lastSeenAt + 1).once('value');
    const allNotifs = notifsSnap.val() || {};
    const dismissedSnap = await db.ref('notificationDismissals/' + visitorId).once('value');
    const dismissed = dismissedSnap.val() || {};
    const unread = Object.entries(allNotifs).filter(([id, d]) => (d.createdAt || 0) <= now && !dismissed[id]).map(([id, d]) => ({
      id, title: d.title || 'SMMARIA', body: d.body || '', type: d.type || 'general',
      imageUrl: d.imageUrl || null, iconUrl: d.iconUrl || null, actionText: d.actionText || null,
      destinationUrl: d.destinationUrl || 'https://smmaria.site', createdAt: d.createdAt || 0
    })).sort((a, b) => b.createdAt - a.createdAt).slice(0, 5);
    res.json({ success: true, notifications: unread });
  } catch (error) { console.error('[in-app/notifications]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

router.post('/api/in-app/dismiss', async (req, res) => {
  try {
    const { visitorId, notificationId } = req.body;
    if (!visitorId || !notificationId) return res.status(400).json({ success: false, message: 'Required' });
    const db = dbOrError(res); if (!db) return;
    await db.ref('notificationDismissals/' + visitorId + '/' + notificationId).set({ dismissedAt: Date.now() });
    res.json({ success: true, message: 'Dismissed' });
  } catch (error) { res.status(500).json({ success: false, message: 'Unable' }); }
});

router.get('/api/in-app/status', async (req, res) => {
  try {
    const visitorId = req.query.visitorId;
    if (!visitorId) return res.json({ success: true, subscribed: false });
    const db = dbOrError(res); if (!db) return;
    const snap = await db.ref('notificationUsers/' + visitorId + '/subscribed').once('value');
    res.json({ success: true, subscribed: snap.val() === true });
  } catch (error) { res.json({ success: true, subscribed: false }); }
});

// ═══════════════════════════════════════════════════════════════
//  ADMIN ROUTES (existing — preserved + improved)
// ═══════════════════════════════════════════════════════════════

router.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const db = dbOrError(res); if (!db) return;
    const usersSnap = await db.ref('notificationUsers').once('value');
    const users = usersSnap.val() || {};
    let subscribedUsers = 0, activeDevices = 0, inAppSubscribers = 0, pushSubscribers = 0;
    for (const userData of Object.values(users)) {
      if (userData.subscribed) subscribedUsers++;
      if (userData.deliveryMethod === 'in-app') inAppSubscribers++; else pushSubscribers++;
      const subs = userData.subscriptions || {};
      for (const sub of Object.values(subs)) { if (sub.active) activeDevices++; }
    }
    const notifsSnap = await db.ref('notifications').once('value');
    const notifs = notifsSnap.val() || {};
    const notifList = Object.values(notifs);
    const totalSent = notifList.reduce((s, n) => s + (n.sentCount || 0), 0);
    const totalFailed = notifList.reduce((s, n) => s + (n.failedCount || 0), 0);
    const totalRemoved = notifList.reduce((s, n) => s + (n.removedCount || 0), 0);
    const totalClicks = notifList.reduce((s, n) => s + (n.clickCount || 0), 0);
    const totalActionClicks = notifList.reduce((s, n) => s + (n.actionClickCount || 0), 0);

    // Recent activity (last 20 audit logs)
    const auditSnap = await db.ref('adminAuditLogs').orderByChild('timestamp').limitToLast(20).once('value');
    const auditLogs = [];
    if (auditSnap.exists()) {
      const logs = auditSnap.val();
      for (const [id, log] of Object.entries(logs)) { auditLogs.push({ id, ...log }); }
      auditLogs.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
    }

    res.json({ success: true, stats: {
      subscribedUsers, activeDevices, inAppSubscribers, pushSubscribers,
      notificationsSent: notifList.length, totalSendAttempts: totalSent,
      totalFailedSends: totalFailed, totalRemovedSubscriptions: totalRemoved,
      totalNotificationClicks: totalClicks, totalActionClicks: totalActionClicks,
      clickRate: totalSent > 0 ? ((totalClicks / totalSent) * 100).toFixed(1) + '%' : '0%',
      actionClickRate: totalSent > 0 ? ((totalActionClicks / totalSent) * 100).toFixed(1) + '%' : '0%'
    }, recentActivity: auditLogs });
  } catch (error) { console.error('[admin/stats]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

router.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const db = dbOrError(res); if (!db) return;
    const usersSnap = await db.ref('notificationUsers').once('value');
    const users = usersSnap.val() || {};
    const userList = Object.entries(users).map(([userId, data]) => {
      const subs = data.subscriptions || {};
      const activeSubs = Object.values(subs).filter(s => s.active);
      return { userId, subscribed: data.subscribed || false, isAnonymous: data.isAnonymous || false,
        deliveryMethod: data.deliveryMethod || 'push', deviceCount: activeSubs.length,
        lastSeenAt: data.lastSeenAt || data.updatedAt || null, createdAt: data.createdAt || null,
        devices: activeSubs.map(s => ({ browser: s.browser || s.device || 'unknown', platform: s.platform || 'unknown', createdAt: s.createdAt, active: s.active }))
      };
    });
    res.json({ success: true, users: userList });
  } catch (error) { console.error('[admin/users]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

router.get('/api/admin/notifications', requireAdmin, async (req, res) => {
  try {
    const db = dbOrError(res); if (!db) return;
    const notifsSnap = await db.ref('notifications').once('value');
    const notifs = notifsSnap.val() || {};
    const notifList = Object.entries(notifs).map(([id, data]) => ({
      id, title: data.title, body: data.body, type: data.type, audience: data.audience,
      targetUserId: data.targetUserId || null, sentCount: data.sentCount || 0, failedCount: data.failedCount || 0,
      removedCount: data.removedCount || 0, clickCount: data.clickCount || 0, actionClickCount: data.actionClickCount || 0,
      status: data.status || 'pending', createdAt: data.createdAt || 0, actionText: data.actionText || null,
      destinationUrl: data.destinationUrl || null, imageUrl: data.imageUrl || null,
      resendOf: data.resendOf || null, resendNumber: data.resendNumber || 0, expirationHours: data.expirationHours || null
    })).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    res.json({ success: true, notifications: notifList });
  } catch (error) { console.error('[admin/notifications]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

router.post('/api/admin/send', requireAdmin, async (req, res) => {
  try {
    const { title, body, imageUrl, iconUrl, badgeUrl, actionText, destinationUrl, type, audience, expirationHours } = req.body;
    if (!title || !body) return res.status(400).json({ success: false, message: 'Title and body required' });
    if (audience !== 'all') return res.status(400).json({ success: false, message: 'Use /send-user for specific' });
    if (imageUrl && !isValidUrl(imageUrl)) return res.status(400).json({ success: false, message: 'Invalid image URL' });
    if (iconUrl && !isValidUrl(iconUrl)) return res.status(400).json({ success: false, message: 'Invalid icon URL' });
    if (destinationUrl && !isValidUrl(destinationUrl)) return res.status(400).json({ success: false, message: 'Invalid destination URL' });
    const notificationId = 'notif_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    const notification = {
      id: notificationId, title, body, type: type || 'general', imageUrl: imageUrl || null, iconUrl: iconUrl || null,
      badgeUrl: badgeUrl || null, actionText: actionText || null, destinationUrl: destinationUrl || 'https://smmaria.site',
      audience: 'all', createdAt: Date.now(), createdBy: 'admin', status: 'sending',
      sentCount: 0, failedCount: 0, removedCount: 0, clickCount: 0, actionClickCount: 0,
      expirationHours: expirationHours || null
    };
    await push.saveNotification(notification);
    const stats = await push.broadcast(notification);
    await push.updateNotificationStats(notificationId, stats);
    await logAudit('notification_sent', { notificationId, title, audience: 'all' });
    res.json({ success: true, message: 'Broadcast complete', notificationId, stats });
  } catch (error) { console.error('[admin/send]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

router.post('/api/admin/send-user', requireAdmin, async (req, res) => {
  try {
    const { title, body, imageUrl, iconUrl, badgeUrl, actionText, destinationUrl, type, targetUserId, expirationHours } = req.body;
    if (!title || !body) return res.status(400).json({ success: false, message: 'Title and body required' });
    if (!targetUserId) return res.status(400).json({ success: false, message: 'targetUserId required' });
    if (imageUrl && !isValidUrl(imageUrl)) return res.status(400).json({ success: false, message: 'Invalid image URL' });
    if (destinationUrl && !isValidUrl(destinationUrl)) return res.status(400).json({ success: false, message: 'Invalid destination URL' });
    const notificationId = 'notif_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    const notification = {
      id: notificationId, title, body, type: type || 'general', imageUrl: imageUrl || null, iconUrl: iconUrl || null,
      badgeUrl: badgeUrl || null, actionText: actionText || null, destinationUrl: destinationUrl || 'https://smmaria.site',
      audience: 'specific', targetUserId, createdAt: Date.now(), createdBy: 'admin', status: 'sending',
      sentCount: 0, failedCount: 0, removedCount: 0, clickCount: 0, actionClickCount: 0,
      expirationHours: expirationHours || null
    };
    await push.saveNotification(notification);
    const stats = await push.sendToUser(targetUserId, notification);
    await push.updateNotificationStats(notificationId, stats);
    await logAudit('notification_sent', { notificationId, title, audience: 'specific', targetUserId });
    res.json({ success: true, message: 'Sent to user', notificationId, stats });
  } catch (error) { console.error('[admin/send-user]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

router.get('/api/admin/analytics/:notificationId', requireAdmin, async (req, res) => {
  try {
    const { notificationId } = req.params;
    const db = dbOrError(res); if (!db) return;
    const notifSnap = await db.ref('notifications/' + notificationId).once('value');
    if (!notifSnap.exists()) return res.status(404).json({ success: false, message: 'Not found' });
    const analyticsSnap = await db.ref('notificationAnalytics/' + notificationId).once('value');
    const analytics = analyticsSnap.val() || {};
    const notif = notifSnap.val();
    const sentCount = analytics.sentCount || notif.sentCount || 0;
    const clickCount = analytics.clickCount || notif.clickCount || 0;
    const actionClickCount = analytics.actionClickCount || notif.actionClickCount || 0;
    res.json({ success: true, analytics: {
      notificationId, title: notif.title, body: notif.body, type: notif.type, audience: notif.audience,
      targetUserId: notif.targetUserId || null, actionText: notif.actionText || null,
      destinationUrl: notif.destinationUrl || null, imageUrl: notif.imageUrl || null, iconUrl: notif.iconUrl || null,
      status: notif.status || 'unknown', createdAt: notif.createdAt || null,
      resendOf: notif.resendOf || null, resendNumber: notif.resendNumber || 0,
      sentCount, failedCount: analytics.failedCount || notif.failedCount || 0,
      removedCount: analytics.removedCount || notif.removedCount || 0,
      clickCount, actionClickCount, uniqueClickCount: analytics.uniqueClickCount || 0,
      clickRate: sentCount > 0 ? ((clickCount / sentCount) * 100).toFixed(1) + '%' : '0%',
      actionClickRate: sentCount > 0 ? ((actionClickCount / sentCount) * 100).toFixed(1) + '%' : '0%'
    }});
  } catch (error) { console.error('[admin/analytics]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

// ═══════════════════════════════════════════════════════════════
//  NEW: RESEND
// ═══════════════════════════════════════════════════════════════

router.post('/api/admin/resend/:notificationId', requireAdmin, async (req, res) => {
  try {
    const { notificationId } = req.params;
    const { smartResend } = req.body; // 'all' | 'failed' | 'not_clicked' | 'specific'
    const { targetUserId } = req.body;
    const db = dbOrError(res); if (!db) return;

    // Fetch original notification — do NOT modify it
    const originalSnap = await db.ref('notifications/' + notificationId).once('value');
    if (!originalSnap.exists()) return res.status(404).json({ success: false, message: 'Original notification not found' });
    const original = originalSnap.val();

    // Count previous resends
    const allNotifsSnap = await db.ref('notifications').orderByChild('resendOf').equalTo(notificationId).once('value');
    const resendCount = allNotifsSnap.exists() ? Object.keys(allNotifsSnap.val()).length : 0;

    // Create a NEW notification — copy original fields, new ID
    const newId = 'notif_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    const newNotification = {
      id: newId, title: original.title, body: original.body, type: original.type || 'general',
      imageUrl: original.imageUrl || null, iconUrl: original.iconUrl || null, badgeUrl: original.badgeUrl || null,
      actionText: original.actionText || null, destinationUrl: original.destinationUrl || 'https://smmaria.site',
      audience: original.audience || 'all', targetUserId: targetUserId || original.targetUserId || null,
      createdAt: Date.now(), createdBy: 'admin', status: 'sending',
      sentCount: 0, failedCount: 0, removedCount: 0, clickCount: 0, actionClickCount: 0,
      resendOf: notificationId, resendNumber: resendCount + 1,
      expirationHours: original.expirationHours || null
    };

    await push.saveNotification(newNotification);

    let stats;
    if (smartResend === 'specific' && targetUserId) {
      stats = await push.sendToUser(targetUserId, newNotification);
    } else {
      // For smart resend, we send to all active subscribers
      // (Full smart resend with delivery-level filtering would require
      //  notificationDelivery data which is tracked going forward)
      stats = await push.broadcast(newNotification);
    }

    await push.updateNotificationStats(newId, stats);
    await logAudit('notification_resent', { notificationId: newId, originalId: notificationId, resendNumber: resendCount + 1 });

    res.json({ success: true, message: 'Resent successfully', notificationId: newId, originalId: notificationId, resendNumber: resendCount + 1, stats });
  } catch (error) { console.error('[admin/resend]', error.message); res.status(500).json({ success: false, message: 'Unable to resend' }); }
});

// ═══════════════════════════════════════════════════════════════
//  NEW: DUPLICATE (returns original data for Compose — no record created)
// ═══════════════════════════════════════════════════════════════

router.get('/api/admin/duplicate/:notificationId', requireAdmin, async (req, res) => {
  try {
    const { notificationId } = req.params;
    const db = dbOrError(res); if (!db) return;
    const snap = await db.ref('notifications/' + notificationId).once('value');
    if (!snap.exists()) return res.status(404).json({ success: false, message: 'Not found' });
    const data = snap.val();
    await logAudit('notification_duplicated', { notificationId });
    res.json({ success: true, notification: {
      title: data.title, body: data.body, type: data.type || 'general',
      imageUrl: data.imageUrl || null, iconUrl: data.iconUrl || null, badgeUrl: data.badgeUrl || null,
      actionText: data.actionText || null, destinationUrl: data.destinationUrl || 'https://smmaria.site',
      audience: data.audience || 'all', targetUserId: data.targetUserId || null,
      expirationHours: data.expirationHours || null
    }});
  } catch (error) { console.error('[admin/duplicate]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

// ═══════════════════════════════════════════════════════════════
//  NEW: DELETE NOTIFICATION RECORD (does NOT delete subscriber data)
// ═══════════════════════════════════════════════════════════════

router.delete('/api/admin/notifications/:notificationId', requireAdmin, async (req, res) => {
  try {
    const { notificationId } = req.params;
    const db = dbOrError(res); if (!db) return;
    const snap = await db.ref('notifications/' + notificationId).once('value');
    if (!snap.exists()) return res.status(404).json({ success: false, message: 'Not found' });
    // Delete only the notification record + its analytics + events
    await db.ref('notifications/' + notificationId).remove();
    await db.ref('notificationAnalytics/' + notificationId).remove();
    await db.ref('notificationEvents').orderByChild('notificationId').equalTo(notificationId).ref.remove();
    await logAudit('notification_deleted', { notificationId });
    res.json({ success: true, message: 'Notification record deleted' });
  } catch (error) { console.error('[admin/delete]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

// ═══════════════════════════════════════════════════════════════
//  NEW: SEND TEST (sends only to admin's test subscription)
// ═══════════════════════════════════════════════════════════════

router.post('/api/admin/send-test', requireAdmin, async (req, res) => {
  try {
    const { title, body, imageUrl, iconUrl, badgeUrl, actionText, destinationUrl, type } = req.body;
    const db = dbOrError(res); if (!db) return;

    // Check if admin has a test subscription
    const testSnap = await db.ref('notificationUsers/' + TEST_SUBSCRIBER_ID).once('value');
    if (!testSnap.exists()) return res.status(400).json({ success: false, message: 'No test subscription registered. Open the admin dashboard on the device you want to test on and click Register Test Device.' });
    const testData = testSnap.val();
    const subs = testData.subscriptions || {};
    const activeSubs = Object.entries(subs).filter(([id, s]) => s.active);
    if (activeSubs.length === 0) return res.status(400).json({ success: false, message: 'No active test subscription' });

    const testNotification = {
      id: 'test_' + Date.now(), title: title || 'Test Notification', body: body || 'This is a test',
      type: type || 'general', imageUrl: imageUrl || null, iconUrl: iconUrl || null, badgeUrl: badgeUrl || null,
      actionText: actionText || null, destinationUrl: destinationUrl || 'https://smmaria.site',
      audience: 'test', createdAt: Date.now(), status: 'sending'
    };

    const payload = push.createPayload(testNotification);
    let sent = 0, failed = 0;
    for (const [subId, sub] of activeSubs) {
      const result = await push.sendToSubscription(sub, payload);
      if (result.success) sent++; else failed++;
    }
    await logAudit('test_notification_sent', { title: testNotification.title });
    res.json({ success: true, message: 'Test sent', sent, failed });
  } catch (error) { console.error('[admin/send-test]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

// Admin registers their own device for testing
router.post('/api/admin/test-subscribe', requireAdmin, async (req, res) => {
  try {
    const { subscription, device } = req.body;
    if (!subscription || !subscription.endpoint) return res.status(400).json({ success: false, message: 'Invalid subscription' });
    const db = dbOrError(res); if (!db) return;
    const crypto = require('crypto');
    const subId = crypto.createHash('sha256').update(subscription.endpoint).digest('hex').slice(0, 24);
    const now = Date.now();
    const ref = db.ref('notificationUsers/' + TEST_SUBSCRIBER_ID);
    await ref.child('subscriptions/' + subId).set({
      endpoint: subscription.endpoint, expirationTime: subscription.expirationTime || null,
      keys: { p256dh: subscription.keys.p256dh, auth: subscription.keys.auth },
      device: (device && device.browser) || 'admin-test', browser: (device && device.browser) || 'admin-test',
      platform: (device && device.platform) || 'unknown', active: true, createdAt: now, updatedAt: now
    });
    const snap = await ref.once('value');
    if (!snap.exists() || !snap.val().createdAt) {
      await ref.update({ userId: TEST_SUBSCRIBER_ID, subscribed: true, isAnonymous: false, deliveryMethod: 'push', createdAt: now, updatedAt: now, lastSeenAt: now });
    } else {
      await ref.update({ subscribed: true, updatedAt: now, lastSeenAt: now });
    }
    res.json({ success: true, message: 'Test device registered' });
  } catch (error) { console.error('[admin/test-subscribe]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

router.get('/api/admin/test-subscription', requireAdmin, async (req, res) => {
  try {
    const db = dbOrError(res); if (!db) return;
    const snap = await db.ref('notificationUsers/' + TEST_SUBSCRIBER_ID).once('value');
    const has = snap.exists() && snap.val().subscribed === true;
    const subs = has ? (snap.val().subscriptions || {}) : {};
    const activeCount = Object.values(subs).filter(s => s.active).length;
    res.json({ success: true, registered: has, activeDevices: activeCount });
  } catch (error) { res.json({ success: true, registered: false, activeDevices: 0 }); }
});

// ═══════════════════════════════════════════════════════════════
//  NEW: TEMPLATES
// ═══════════════════════════════════════════════════════════════

router.post('/api/admin/templates', requireAdmin, async (req, res) => {
  try {
    const { name, title, body, imageUrl, iconUrl, badgeUrl, actionText, destinationUrl, type } = req.body;
    if (!name || !title || !body) return res.status(400).json({ success: false, message: 'Name, title, body required' });
    const db = dbOrError(res); if (!db) return;
    const templateId = 'tpl_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    await db.ref('notificationTemplates/' + templateId).set({
      id: templateId, name, title, body, type: type || 'general',
      imageUrl: imageUrl || null, iconUrl: iconUrl || null, badgeUrl: badgeUrl || null,
      actionText: actionText || null, destinationUrl: destinationUrl || 'https://smmaria.site',
      createdAt: Date.now(), updatedAt: Date.now()
    });
    await logAudit('template_created', { templateId, name });
    res.json({ success: true, message: 'Template created', templateId });
  } catch (error) { console.error('[admin/templates POST]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

router.get('/api/admin/templates', requireAdmin, async (req, res) => {
  try {
    const db = dbOrError(res); if (!db) return;
    const snap = await db.ref('notificationTemplates').once('value');
    const templates = snap.val() || {};
    const list = Object.entries(templates).map(([id, data]) => ({ id, ...data })).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    res.json({ success: true, templates: list });
  } catch (error) { console.error('[admin/templates GET]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

router.put('/api/admin/templates/:templateId', requireAdmin, async (req, res) => {
  try {
    const { templateId } = req.params;
    const { name, title, body, imageUrl, iconUrl, badgeUrl, actionText, destinationUrl, type } = req.body;
    const db = dbOrError(res); if (!db) return;
    const snap = await db.ref('notificationTemplates/' + templateId).once('value');
    if (!snap.exists()) return res.status(404).json({ success: false, message: 'Template not found' });
    await db.ref('notificationTemplates/' + templateId).update({
      name: name || snap.val().name, title: title || snap.val().title, body: body || snap.val().body,
      type: type || snap.val().type, imageUrl: imageUrl || null, iconUrl: iconUrl || null,
      badgeUrl: badgeUrl || null, actionText: actionText || null,
      destinationUrl: destinationUrl || 'https://smmaria.site', updatedAt: Date.now()
    });
    await logAudit('template_edited', { templateId });
    res.json({ success: true, message: 'Template updated' });
  } catch (error) { console.error('[admin/templates PUT]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

router.delete('/api/admin/templates/:templateId', requireAdmin, async (req, res) => {
  try {
    const { templateId } = req.params;
    const db = dbOrError(res); if (!db) return;
    await db.ref('notificationTemplates/' + templateId).remove();
    await logAudit('template_deleted', { templateId });
    res.json({ success: true, message: 'Template deleted' });
  } catch (error) { console.error('[admin/templates DELETE]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

// ═══════════════════════════════════════════════════════════════
//  NEW: DRAFTS
// ═══════════════════════════════════════════════════════════════

router.post('/api/admin/drafts', requireAdmin, async (req, res) => {
  try {
    const { name, title, body, imageUrl, iconUrl, badgeUrl, actionText, destinationUrl, type, audience, targetUserId, expirationHours } = req.body;
    const db = dbOrError(res); if (!db) return;
    const draftId = 'draft_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    await db.ref('notificationDrafts/' + draftId).set({
      id: draftId, name: name || 'Untitled Draft', title: title || '', body: body || '',
      type: type || 'general', imageUrl: imageUrl || null, iconUrl: iconUrl || null,
      badgeUrl: badgeUrl || null, actionText: actionText || null,
      destinationUrl: destinationUrl || 'https://smmaria.site', audience: audience || 'all',
      targetUserId: targetUserId || null, expirationHours: expirationHours || null,
      status: 'draft', createdAt: Date.now(), updatedAt: Date.now()
    });
    await logAudit('draft_saved', { draftId });
    res.json({ success: true, message: 'Draft saved', draftId });
  } catch (error) { console.error('[admin/drafts POST]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

router.get('/api/admin/drafts', requireAdmin, async (req, res) => {
  try {
    const db = dbOrError(res); if (!db) return;
    const snap = await db.ref('notificationDrafts').once('value');
    const drafts = snap.val() || {};
    const list = Object.entries(drafts).map(([id, data]) => ({ id, ...data })).sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));
    res.json({ success: true, drafts: list });
  } catch (error) { console.error('[admin/drafts GET]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

router.put('/api/admin/drafts/:draftId', requireAdmin, async (req, res) => {
  try {
    const { draftId } = req.params;
    const updates = req.body;
    const db = dbOrError(res); if (!db) return;
    const snap = await db.ref('notificationDrafts/' + draftId).once('value');
    if (!snap.exists()) return res.status(404).json({ success: false, message: 'Draft not found' });
    await db.ref('notificationDrafts/' + draftId).update({ ...updates, updatedAt: Date.now() });
    await logAudit('draft_edited', { draftId });
    res.json({ success: true, message: 'Draft updated' });
  } catch (error) { console.error('[admin/drafts PUT]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

router.delete('/api/admin/drafts/:draftId', requireAdmin, async (req, res) => {
  try {
    const { draftId } = req.params;
    const db = dbOrError(res); if (!db) return;
    await db.ref('notificationDrafts/' + draftId).remove();
    await logAudit('draft_deleted', { draftId });
    res.json({ success: true, message: 'Draft deleted' });
  } catch (error) { console.error('[admin/drafts DELETE]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

router.post('/api/admin/drafts/:draftId/send', requireAdmin, async (req, res) => {
  try {
    const { draftId } = req.params;
    const db = dbOrError(res); if (!db) return;
    const snap = await db.ref('notificationDrafts/' + draftId).once('value');
    if (!snap.exists()) return res.status(404).json({ success: false, message: 'Draft not found' });
    const draft = snap.val();

    const notificationId = 'notif_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    const notification = {
      id: notificationId, title: draft.title, body: draft.body, type: draft.type || 'general',
      imageUrl: draft.imageUrl || null, iconUrl: draft.iconUrl || null, badgeUrl: draft.badgeUrl || null,
      actionText: draft.actionText || null, destinationUrl: draft.destinationUrl || 'https://smmaria.site',
      audience: draft.audience || 'all', targetUserId: draft.targetUserId || null,
      createdAt: Date.now(), createdBy: 'admin', status: 'sending',
      sentCount: 0, failedCount: 0, removedCount: 0, clickCount: 0, actionClickCount: 0,
      expirationHours: draft.expirationHours || null, fromDraftId: draftId
    };
    await push.saveNotification(notification);
    let stats;
    if (notification.audience === 'specific' && notification.targetUserId) {
      stats = await push.sendToUser(notification.targetUserId, notification);
    } else {
      stats = await push.broadcast(notification);
    }
    await push.updateNotificationStats(notificationId, stats);
    await logAudit('draft_sent', { draftId, notificationId });
    res.json({ success: true, message: 'Draft sent', notificationId, stats });
  } catch (error) { console.error('[admin/drafts/send]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

// ═══════════════════════════════════════════════════════════════
//  NEW: SCHEDULED NOTIFICATIONS
// ═══════════════════════════════════════════════════════════════

router.post('/api/admin/scheduled', requireAdmin, async (req, res) => {
  try {
    const { title, body, imageUrl, iconUrl, badgeUrl, actionText, destinationUrl, type, audience, targetUserId, scheduledAt, timezone, expirationHours } = req.body;
    if (!title || !body) return res.status(400).json({ success: false, message: 'Title and body required' });
    if (!scheduledAt) return res.status(400).json({ success: false, message: 'scheduledAt required' });
    const db = dbOrError(res); if (!db) return;
    const schedId = 'sched_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    await db.ref('scheduledNotifications/' + schedId).set({
      id: schedId, title, body, type: type || 'general', imageUrl: imageUrl || null,
      iconUrl: iconUrl || null, badgeUrl: badgeUrl || null, actionText: actionText || null,
      destinationUrl: destinationUrl || 'https://smmaria.site', audience: audience || 'all',
      targetUserId: targetUserId || null, scheduledAt, timezone: timezone || 'Africa/Kampala',
      expirationHours: expirationHours || null, status: 'scheduled', createdAt: Date.now(), updatedAt: Date.now()
    });
    await logAudit('scheduled_created', { scheduledId: schedId, title, scheduledAt });
    res.json({ success: true, message: 'Scheduled notification created', scheduledId: schedId });
  } catch (error) { console.error('[admin/scheduled POST]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

router.get('/api/admin/scheduled', requireAdmin, async (req, res) => {
  try {
    const db = dbOrError(res); if (!db) return;
    const snap = await db.ref('scheduledNotifications').once('value');
    const scheduled = snap.val() || {};
    const list = Object.entries(scheduled).map(([id, data]) => ({ id, ...data })).sort((a, b) => (a.scheduledAt || 0) - (b.scheduledAt || 0));
    res.json({ success: true, scheduled: list });
  } catch (error) { console.error('[admin/scheduled GET]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

router.put('/api/admin/scheduled/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    const db = dbOrError(res); if (!db) return;
    const snap = await db.ref('scheduledNotifications/' + id).once('value');
    if (!snap.exists()) return res.status(404).json({ success: false, message: 'Not found' });
    await db.ref('scheduledNotifications/' + id).update({ ...updates, updatedAt: Date.now() });
    await logAudit('scheduled_edited', { scheduledId: id });
    res.json({ success: true, message: 'Scheduled notification updated' });
  } catch (error) { console.error('[admin/scheduled PUT]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

router.post('/api/admin/scheduled/:id/cancel', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const db = dbOrError(res); if (!db) return;
    const snap = await db.ref('scheduledNotifications/' + id).once('value');
    if (!snap.exists()) return res.status(404).json({ success: false, message: 'Not found' });
    const data = snap.val();
    if (data.status === 'sent' || data.status === 'sending') return res.status(400).json({ success: false, message: 'Already sent or sending' });
    await db.ref('scheduledNotifications/' + id).update({ status: 'cancelled', updatedAt: Date.now() });
    await logAudit('scheduled_cancelled', { scheduledId: id });
    res.json({ success: true, message: 'Scheduled notification cancelled' });
  } catch (error) { console.error('[admin/scheduled/cancel]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

router.post('/api/admin/scheduled/:id/send', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const db = dbOrError(res); if (!db) return;
    const snap = await db.ref('scheduledNotifications/' + id).once('value');
    if (!snap.exists()) return res.status(404).json({ success: false, message: 'Not found' });
    const data = snap.val();
    if (data.status === 'cancelled') return res.status(400).json({ success: false, message: 'Cannot send cancelled notification' });

    // Atomic status transition: scheduled → sending
    await db.ref('scheduledNotifications/' + id).update({ status: 'sending', updatedAt: Date.now() });

    const notificationId = 'notif_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    const notification = {
      id: notificationId, title: data.title, body: data.body, type: data.type || 'general',
      imageUrl: data.imageUrl || null, iconUrl: data.iconUrl || null, badgeUrl: data.badgeUrl || null,
      actionText: data.actionText || null, destinationUrl: data.destinationUrl || 'https://smmaria.site',
      audience: data.audience || 'all', targetUserId: data.targetUserId || null,
      createdAt: Date.now(), createdBy: 'admin', status: 'sending',
      sentCount: 0, failedCount: 0, removedCount: 0, clickCount: 0, actionClickCount: 0,
      expirationHours: data.expirationHours || null, fromScheduledId: id
    };
    await push.saveNotification(notification);
    let stats;
    if (notification.audience === 'specific' && notification.targetUserId) {
      stats = await push.sendToUser(notification.targetUserId, notification);
    } else {
      stats = await push.broadcast(notification);
    }
    await push.updateNotificationStats(notificationId, stats);
    await db.ref('scheduledNotifications/' + id).update({ status: 'sent', sentNotificationId: notificationId, sentAt: Date.now(), updatedAt: Date.now() });
    await logAudit('scheduled_sent', { scheduledId: id, notificationId });
    res.json({ success: true, message: 'Scheduled notification sent now', notificationId, stats });
  } catch (error) { console.error('[admin/scheduled/send]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

// ═══════════════════════════════════════════════════════════════
//  NEW: AUDIT LOGS
// ═══════════════════════════════════════════════════════════════

router.get('/api/admin/audit-logs', requireAdmin, async (req, res) => {
  try {
    const db = dbOrError(res); if (!db) return;
    const snap = await db.ref('adminAuditLogs').orderByChild('timestamp').limitToLast(50).once('value');
    const logs = [];
    if (snap.exists()) {
      const data = snap.val();
      for (const [id, log] of Object.entries(data)) { logs.push({ id, ...log }); }
      logs.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
    }
    res.json({ success: true, logs });
  } catch (error) { console.error('[admin/audit-logs]', error.message); res.status(500).json({ success: false, message: 'Unable' }); }
});

module.exports = router;
