/**
 * SMMARIA NOTIFICATIONS — Web Push Engine
 *
 * Handles:
 *  - VAPID configuration
 *  - Sending to one subscription
 *  - Sending to all of a user's devices
 *  - Broadcasting to every subscriber
 *  - Invalid subscription cleanup (HTTP 404 / 410)
 *  - Delivery statistics (sent / failed / removed)
 *  - Event recording for idempotency
 *
 * NEVER exposes VAPID_PRIVATE_KEY to the frontend.
 */

const webpush = require('web-push');
const { getDb, isAvailable } = require('./firebase');

// ── VAPID Configuration ──────────────────────────────────────────

function configureVapid() {
  const publicKey = process.env.VAPID_PUBLIC_KEY;
  const privateKey = process.env.VAPID_PRIVATE_KEY;
  const subject = process.env.VAPID_SUBJECT || 'mailto:admin@smmaria.site';

  if (!publicKey || !privateKey) {
    console.warn('[push] VAPID keys not set. Push sending will not work.');
    return false;
  }

  webpush.setVapidDetails(subject, publicKey, privateKey);
  console.log('[push] VAPID configured');
  return true;
}

// ── Payload Creation ─────────────────────────────────────────────

/**
 * Build the JSON payload sent to the service worker.
 * Only includes fields that have values so the SW
 * can gracefully fall back for unsupported features.
 */
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

  return JSON.stringify(payload);
}

// ── Event Recording ──────────────────────────────────────────────

async function recordEvent(notificationId, userId, subscriptionId, event) {
  if (!isAvailable()) return;
  const db = getDb();
  const eventId = `${notificationId}_${subscriptionId || 'na'}_${event}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  try {
    await db.ref(`notificationEvents/${eventId}`).set({
      notificationId,
      userId: userId || null,
      subscriptionId: subscriptionId || null,
      event,
      createdAt: Date.now()
    });
  } catch (e) {
    // Non-fatal — event recording must not break the send
    console.error('[push] Failed to record event:', e.message);
  }
}

// ── Send to One Subscription ─────────────────────────────────────

async function sendToSubscription(subscription, payload) {
  const pushSubscription = {
    endpoint: subscription.endpoint,
    keys: {
      p256dh: subscription.keys.p256dh,
      auth: subscription.keys.auth
    }
  };

  try {
    await webpush.sendNotification(pushSubscription, payload, {
      TTL: 2419200 // 28 days
    });
    return { success: true, invalid: false };
  } catch (error) {
    const statusCode = error.statusCode || error.status;
    // 404 = subscription gone, 410 = subscription unsubscribed
    if (statusCode === 404 || statusCode === 410) {
      return { success: false, invalid: true, error: error.message, statusCode };
    }
    return { success: false, invalid: false, error: error.message, statusCode };
  }
}

// ── Deactivate a subscription ────────────────────────────────────

async function deactivateSubscription(userId, subscriptionId) {
  if (!isAvailable()) return;
  const db = getDb();
  const subRef = db.ref(`notificationUsers/${userId}/subscriptions/${subscriptionId}`);
  await subRef.update({ active: false, updatedAt: Date.now() });
}

// ── Update user's subscribed flag ────────────────────────────────

async function refreshUserSubscribedFlag(userId) {
  if (!isAvailable()) return;
  const db = getDb();
  const userRef = db.ref(`notificationUsers/${userId}`);
  const snap = await userRef.child('subscriptions').once('value');
  const subs = snap.val() || {};
  const hasActive = Object.values(subs).some(s => s.active === true);
  await userRef.update({ subscribed: hasActive, updatedAt: Date.now() });
}

// ── Send to a Specific User (all their devices) ─────────────────

async function sendToUser(userId, notification) {
  const payload = createPayload(notification);
  const stats = { sent: 0, failed: 0, removed: 0 };

  if (!isAvailable()) {
    console.warn('[push] Firebase unavailable — cannot send to user');
    return stats;
  }

  const db = getDb();
  const userRef = db.ref(`notificationUsers/${userId}`);
  const snap = await userRef.once('value');

  if (!snap.exists()) {
    return stats;
  }

  const userData = snap.val();
  const subscriptions = userData.subscriptions || {};

  for (const [subId, sub] of Object.entries(subscriptions)) {
    if (sub.active !== true) continue;

    const result = await sendToSubscription(sub, payload);

    if (result.success) {
      stats.sent++;
      await recordEvent(notification.id, userId, subId, 'sent');
    } else if (result.invalid) {
      stats.removed++;
      await deactivateSubscription(userId, subId);
      await recordEvent(notification.id, userId, subId, 'removed');
    } else {
      stats.failed++;
      await recordEvent(notification.id, userId, subId, 'failed');
    }
  }

  await refreshUserSubscribedFlag(userId);
  return stats;
}

// ── Broadcast to ALL Subscribers ─────────────────────────────────

async function broadcast(notification) {
  const payload = createPayload(notification);
  const stats = { sent: 0, failed: 0, removed: 0 };

  if (!isAvailable()) {
    console.warn('[push] Firebase unavailable — cannot broadcast');
    return stats;
  }

  const db = getDb();
  const usersSnap = await db.ref('notificationUsers').once('value');

  if (!usersSnap.exists()) {
    return stats;
  }

  const users = usersSnap.val();

  for (const [userId, userData] of Object.entries(users)) {
    const subscriptions = userData.subscriptions || {};

    for (const [subId, sub] of Object.entries(subscriptions)) {
      if (sub.active !== true) continue;

      const result = await sendToSubscription(sub, payload);

      if (result.success) {
        stats.sent++;
        await recordEvent(notification.id, userId, subId, 'sent');
      } else if (result.invalid) {
        stats.removed++;
        await deactivateSubscription(userId, subId);
        await recordEvent(notification.id, userId, subId, 'removed');
      } else {
        stats.failed++;
        await recordEvent(notification.id, userId, subId, 'failed');
      }
    }

    // After processing all of this user's subscriptions,
    // refresh their subscribed flag
    await refreshUserSubscribedFlag(userId);
  }

  return stats;
}

// ── Save Notification to Firebase ────────────────────────────────

async function saveNotification(notification) {
  if (!isAvailable()) return notification.id;
  const db = getDb();
  const notifRef = db.ref(`notifications/${notification.id}`);
  await notifRef.set(notification);

  // Also create the analytics node
  await db.ref(`notificationAnalytics/${notification.id}`).set({
    sentCount: 0,
    failedCount: 0,
    removedCount: 0,
    clickCount: 0,
    actionClickCount: 0,
    uniqueClickCount: 0
  });

  return notification.id;
}

// ── Update Notification Statistics ───────────────────────────────

async function updateNotificationStats(notificationId, stats) {
  if (!isAvailable()) return;
  const db = getDb();

  // Update the notification record
  await db.ref(`notifications/${notificationId}`).update({
    sentCount: stats.sent,
    failedCount: stats.failed,
    removedCount: stats.removed,
    status: stats.failed === 0 && stats.removed === 0 ? 'sent' : 'partial',
    updatedAt: Date.now()
  });

  // Update the analytics record
  await db.ref(`notificationAnalytics/${notificationId}`).update({
    sentCount: stats.sent,
    failedCount: stats.failed,
    removedCount: stats.removed
  });
}

// ── Increment Click Counters ─────────────────────────────────────

async function incrementClick(notificationId, event) {
  if (!isAvailable()) return;
  const db = getDb();

  if (event === 'action_click') {
    await db.ref(`notificationAnalytics/${notificationId}`).transaction((current) => {
      const val = current || {};
      val.actionClickCount = (val.actionClickCount || 0) + 1;
      val.clickCount = (val.clickCount || 0) + 1;
      return val;
    });
    await db.ref(`notifications/${notificationId}`).transaction((current) => {
      const val = current || {};
      val.actionClickCount = (val.actionClickCount || 0) + 1;
      val.clickCount = (val.clickCount || 0) + 1;
      return val;
    });
  } else {
    await db.ref(`notificationAnalytics/${notificationId}`).transaction((current) => {
      const val = current || {};
      val.clickCount = (val.clickCount || 0) + 1;
      return val;
    });
    await db.ref(`notifications/${notificationId}`).transaction((current) => {
      const val = current || {};
      val.clickCount = (val.clickCount || 0) + 1;
      return val;
    });
  }
}

module.exports = {
  configureVapid,
  createPayload,
  sendToSubscription,
  sendToUser,
  broadcast,
  saveNotification,
  updateNotificationStats,
  incrementClick,
  recordEvent
};