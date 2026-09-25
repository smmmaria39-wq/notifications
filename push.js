/**
 * SMMARIA NOTIFICATIONS — Web Push Engine (UPGRADED)
 * All existing functions preserved. createPayload updated for expiration.
 */
const webpush = require('web-push');
const { getDb, isAvailable } = require('./firebase');

function configureVapid() {
  const publicKey = process.env.VAPID_PUBLIC_KEY;
  const privateKey = process.env.VAPID_PRIVATE_KEY;
  const subject = process.env.VAPID_SUBJECT || 'mailto:admin@smmaria.site';
  if (!publicKey || !privateKey) { console.warn('[push] VAPID keys not set'); return false; }
  webpush.setVapidDetails(subject, publicKey, privateKey);
  console.log('[push] VAPID configured');
  return true;
}

function createPayload(notification) {
  const payload = {
    title: notification.title || 'SMMARIA',
    body: notification.body || '',
    url: notification.destinationUrl || 'https://smmaria.site',
    type: notification.type || 'general',
    notificationId: notification.id || null
  };
  if (notification.imageUrl) payload.image = notification.imageUrl;
  if (notification.iconUrl) payload.icon = notification.iconUrl;
  if (notification.badgeUrl) payload.badge = notification.badgeUrl;
  if (notification.actionText) payload.actionText = notification.actionText;
  // Expiration support — converted to TTL seconds for Web Push
  if (notification.expirationHours) {
    payload.expirationHours = notification.expirationHours;
  }
  return JSON.stringify(payload);
}

async function recordEvent(notificationId, userId, subscriptionId, event) {
  if (!isAvailable()) return;
  try {
    const db = getDb();
    const eventId = notificationId + '_' + (subscriptionId || 'na') + '_' + event + '_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    await db.ref('notificationEvents/' + eventId).set({ notificationId, userId: userId || null, subscriptionId: subscriptionId || null, event, createdAt: Date.now() });
  } catch (e) { console.error('[push] Event record failed:', e.message); }
}

async function sendToSubscription(subscription, payload) {
  const pushSubscription = { endpoint: subscription.endpoint, keys: { p256dh: subscription.keys.p256dh, auth: subscription.keys.auth } };
  // Calculate TTL from payload if expiration is set
  let options = { TTL: 2419200 }; // 28 days default
  try {
    const parsed = JSON.parse(payload);
    if (parsed.expirationHours) {
      options.TTL = Math.min(parseInt(parsed.expirationHours) * 3600, 2419200);
    }
  } catch (e) {}
  try {
    await webpush.sendNotification(pushSubscription, payload, options);
    return { success: true, invalid: false };
  } catch (error) {
    const statusCode = error.statusCode || error.status;
    if (statusCode === 404 || statusCode === 410) return { success: false, invalid: true, error: error.message, statusCode };
    return { success: false, invalid: false, error: error.message, statusCode };
  }
}

async function deactivateSubscription(userId, subscriptionId) {
  if (!isAvailable()) return;
  try { await getDb().ref('notificationUsers/' + userId + '/subscriptions/' + subscriptionId).update({ active: false, updatedAt: Date.now() }); } catch (e) {}
}

async function refreshUserSubscribedFlag(userId) {
  if (!isAvailable()) return;
  try {
    const db = getDb();
    const snap = await db.ref('notificationUsers/' + userId + '/subscriptions').once('value');
    const subs = snap.val() || {};
    const hasActive = Object.values(subs).some(s => s.active === true);
    await db.ref('notificationUsers/' + userId).update({ subscribed: hasActive, updatedAt: Date.now() });
  } catch (e) {}
}

async function sendToUser(userId, notification) {
  const payload = createPayload(notification);
  const stats = { sent: 0, failed: 0, removed: 0 };
  if (!isAvailable()) return stats;
  const db = getDb();
  const snap = await db.ref('notificationUsers/' + userId).once('value');
  if (!snap.exists()) return stats;
  const subscriptions = snap.val().subscriptions || {};
  for (const [subId, sub] of Object.entries(subscriptions)) {
    if (sub.active !== true) continue;
    const result = await sendToSubscription(sub, payload);
    if (result.success) { stats.sent++; await recordEvent(notification.id, userId, subId, 'sent'); }
    else if (result.invalid) { stats.removed++; await deactivateSubscription(userId, subId); await recordEvent(notification.id, userId, subId, 'removed'); }
    else { stats.failed++; await recordEvent(notification.id, userId, subId, 'failed'); }
  }
  await refreshUserSubscribedFlag(userId);
  return stats;
}

async function broadcast(notification) {
  const payload = createPayload(notification);
  const stats = { sent: 0, failed: 0, removed: 0 };
  if (!isAvailable()) return stats;
  const db = getDb();
  const usersSnap = await db.ref('notificationUsers').once('value');
  if (!usersSnap.exists()) return stats;
  const users = usersSnap.val();
  for (const [userId, userData] of Object.entries(users)) {
    // Skip the admin test subscriber in broadcasts
    if (userId === 'admin_test_subscriber') continue;
    const subscriptions = userData.subscriptions || {};
    for (const [subId, sub] of Object.entries(subscriptions)) {
      if (sub.active !== true) continue;
      const result = await sendToSubscription(sub, payload);
      if (result.success) { stats.sent++; await recordEvent(notification.id, userId, subId, 'sent'); }
      else if (result.invalid) { stats.removed++; await deactivateSubscription(userId, subId); await recordEvent(notification.id, userId, subId, 'removed'); }
      else { stats.failed++; await recordEvent(notification.id, userId, subId, 'failed'); }
    }
    await refreshUserSubscribedFlag(userId);
  }
  return stats;
}

async function saveNotification(notification) {
  if (!isAvailable()) return notification.id;
  const db = getDb();
  await db.ref('notifications/' + notification.id).set(notification);
  await db.ref('notificationAnalytics/' + notification.id).set({ sentCount: 0, failedCount: 0, removedCount: 0, clickCount: 0, actionClickCount: 0, uniqueClickCount: 0 });
  return notification.id;
}

async function updateNotificationStats(notificationId, stats) {
  if (!isAvailable()) return;
  const db = getDb();
  await db.ref('notifications/' + notificationId).update({
    sentCount: stats.sent, failedCount: stats.failed, removedCount: stats.removed,
    status: stats.failed === 0 && stats.removed === 0 ? 'sent' : 'partially_sent', updatedAt: Date.now()
  });
  await db.ref('notificationAnalytics/' + notificationId).update({
    sentCount: stats.sent, failedCount: stats.failed, removedCount: stats.removed
  });
}

async function incrementClick(notificationId, event) {
  if (!isAvailable()) return;
  const db = getDb();
  if (event === 'action_click') {
    await db.ref('notificationAnalytics/' + notificationId).transaction(c => { const v = c || {}; v.actionClickCount = (v.actionClickCount || 0) + 1; v.clickCount = (v.clickCount || 0) + 1; return v; });
    await db.ref('notifications/' + notificationId).transaction(c => { const v = c || {}; v.actionClickCount = (v.actionClickCount || 0) + 1; v.clickCount = (v.clickCount || 0) + 1; return v; });
  } else {
    await db.ref('notificationAnalytics/' + notificationId).transaction(c => { const v = c || {}; v.clickCount = (v.clickCount || 0) + 1; return v; });
    await db.ref('notifications/' + notificationId).transaction(c => { const v = c || {}; v.clickCount = (v.clickCount || 0) + 1; return v; });
  }
}

// ── NEW: Process scheduled notifications (called by server.js) ──
async function processScheduledNotifications() {
  if (!isAvailable()) return;
  const db = getDb();
  const now = Date.now();
  try {
    const snap = await db.ref('scheduledNotifications').orderByChild('scheduledAt').endAt(now).once('value');
    if (!snap.exists()) return;
    const pending = snap.val();
    for (const [id, data] of Object.entries(pending)) {
      if (data.status !== 'scheduled') continue; // Skip cancelled/sent/sending
      // Atomic transition: scheduled → sending
      await db.ref('scheduledNotifications/' + id).update({ status: 'sending', updatedAt: now });
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
      await saveNotification(notification);
      let stats;
      if (notification.audience === 'specific' && notification.targetUserId) {
        stats = await sendToUser(notification.targetUserId, notification);
      } else {
        stats = await broadcast(notification);
      }
      await updateNotificationStats(notificationId, stats);
      await db.ref('scheduledNotifications/' + id).update({ status: 'sent', sentNotificationId: notificationId, sentAt: Date.now(), updatedAt: Date.now() });
      try { await db.ref('adminAuditLogs/log_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8)).set({ action: 'scheduled_auto_sent', notificationId, scheduledId: id, timestamp: Date.now() }); } catch (e) {}
      console.log('[push] Scheduled notification processed:', id, '→', notificationId);
    }
  } catch (e) { console.error('[push] Scheduled processing error:', e.message); }
}

module.exports = {
  configureVapid, createPayload, sendToSubscription, sendToUser, broadcast,
  saveNotification, updateNotificationStats, incrementClick, recordEvent,
  processScheduledNotifications
};
