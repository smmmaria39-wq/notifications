/**
 * SMMARIA NOTIFICATIONS — API Routes
 *
 * PUBLIC:
 *   GET  /api/health
 *   GET  /api/config
 *   POST /api/subscribe            (JWT optional — anonymous OK)
 *   POST /api/unsubscribe           (JWT optional — anonymous OK)
 *   GET  /api/subscription/status   (JWT optional — anonymous OK)
 *   POST /api/analytics/click       (rate-limited, validated)
 *
 * ADMIN (requires x-admin-key header):
 *   GET  /api/admin/stats
 *   GET  /api/admin/users
 *   GET  /api/admin/notifications
 *   POST /api/admin/send
 *   POST /api/admin/send-user
 *   GET  /api/admin/analytics/:notificationId
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const { getDb, isAvailable } = require('./firebase');
const push = require('./push');

const router = express.Router();

// ═══════════════════════════════════════════════════════════════
//  MIDDLEWARE & HELPERS
// ═══════════════════════════════════════════════════════════════

const ADMIN_KEY = process.env.ADMIN_KEY;
const JWT_SECRET = process.env.SMMARIA_JWT_SECRET;
const JWT_USER_ID_CLAIM = process.env.SMMARIA_JWT_USER_ID_CLAIM || 'userId';
const DEV_MODE = process.env.DEV_MODE === 'true';

// ── Simple in-memory rate limiter ────────────────────────────────
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

// Clean up old entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [k, entries] of rateLimitMap.entries()) {
    const valid = entries.filter(ts => now - ts < 60000);
    if (valid.length === 0) rateLimitMap.delete(k);
    else rateLimitMap.set(k, valid);
  }
}, 300000);

// ── Admin Authentication ─────────────────────────────────────────

function requireAdmin(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (!ADMIN_KEY) {
    return res.status(500).json({
      success: false,
      message: 'ADMIN_KEY not configured on the server'
    });
  }
  if (!key || key !== ADMIN_KEY) {
    return res.status(401).json({
      success: false,
      message: 'Unauthorized — invalid admin key'
    });
  }
  next();
}

// ── User Identity Verification (JWT) — STRICT ───────────────────
// Used for admin-only user-specific operations.

function verifyUser(req, res, next) {
  if (DEV_MODE) {
    const userId = req.headers['x-user-id'] || (req.body && req.body.userId);
    if (!userId) {
      return res.status(401).json({
        success: false,
        message: 'User ID required (DEV_MODE)'
      });
    }
    req.userId = userId;
    return next();
  }

  if (!JWT_SECRET) {
    return res.status(500).json({
      success: false,
      message: 'SMMARIA_JWT_SECRET not configured. Cannot verify user identity.'
    });
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      message: 'Authentication token required'
    });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded[JWT_USER_ID_CLAIM] || decoded.sub || decoded.id || decoded.userId;
    if (!userId) {
      return res.status(401).json({
        success: false,
        message: 'Token does not contain a valid user ID claim'
      });
    }
    req.userId = String(userId);
    next();
  } catch (err) {
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired authentication token'
    });
  }
}

// ── Optional User Verification — ALLOWS ANONYMOUS ───────────────
// Same as verifyUser but does NOT fail if no token is present.
// If JWT is valid → req.userId is set to the real user ID.
// If no JWT or invalid JWT → req.userId is null (anonymous).
// Used for subscribe / unsubscribe / subscription status.

function optionalVerifyUser(req, res, next) {
  if (DEV_MODE) {
    req.userId = req.headers['x-user-id'] || (req.body && req.body.userId) || null;
    return next();
  }

  if (!JWT_SECRET) {
    // No JWT secret configured — allow anonymous (no userId)
    req.userId = null;
    return next();
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    // No token — anonymous user
    req.userId = null;
    return next();
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded[JWT_USER_ID_CLAIM] || decoded.sub || decoded.id || decoded.userId;
    req.userId = userId ? String(userId) : null;
  } catch (err) {
    // Invalid or expired token — treat as anonymous, do NOT reject
    req.userId = null;
  }
  next();
}

// ── URL Validation ───────────────────────────────────────────────

function isValidUrl(url) {
  if (!url) return false;
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

// ── Safe Firebase getter ─────────────────────────────────────────

function dbOrError(res) {
  if (!isAvailable()) {
    res.status(503).json({
      success: false,
      message: 'Notification database is unavailable'
    });
    return null;
  }
  return getDb();
}

// ── Helper: check if a user is subscribed ────────────────────────

async function isUserSubscribed(userId) {
  if (!isAvailable()) return false;
  const db = getDb();
  const snap = await db.ref('notificationUsers/' + userId + '/subscribed').once('value');
  return snap.val() === true;
}

// ═══════════════════════════════════════════════════════════════
//  PUBLIC ROUTES
// ═══════════════════════════════════════════════════════════════

// ── GET /api/health ─────────────────────────────────────────────

router.get('/api/health', (req, res) => {
  res.json({
    success: true,
    service: 'SMMARIA Notification Service',
    status: 'online',
    firebase: isAvailable() ? 'connected' : 'disconnected',
    timestamp: Date.now()
  });
});

// ── GET /api/config ─────────────────────────────────────────────

router.get('/api/config', (req, res) => {
  res.json({
    success: true,
    vapidPublicKey: process.env.VAPID_PUBLIC_KEY || null
  });
});

// ── POST /api/subscribe (anonymous + authenticated) ────────────

router.post('/api/subscribe', optionalVerifyUser, async (req, res) => {
  try {
    const { subscription, device } = req.body;

    if (!subscription || !subscription.endpoint || !subscription.keys) {
      return res.status(400).json({
        success: false,
        message: 'Invalid PushSubscription — endpoint and keys are required'
      });
    }

    const db = dbOrError(res);
    if (!db) return;

    // Generate a stable subscription ID from the endpoint hash
    const crypto = require('crypto');
    const subId = crypto
      .createHash('sha256')
      .update(subscription.endpoint)
      .digest('hex')
      .slice(0, 24);

    // If user is authenticated (has valid JWT), use their userId.
    // If anonymous (no JWT), use anonymous_{subId} as the identifier.
    const userId = req.userId || ('anonymous_' + subId);
    const isAnonymous = !req.userId;
    const now = Date.now();

    const userRef = db.ref('notificationUsers/' + userId);
    const subRef = userRef.child('subscriptions/' + subId);

    // Save the subscription
    await subRef.set({
      endpoint: subscription.endpoint,
      expirationTime: subscription.expirationTime || null,
      keys: {
        p256dh: subscription.keys.p256dh,
        auth: subscription.keys.auth
      },
      device: (device && device.browser) || 'unknown',
      browser: (device && device.browser) || 'unknown',
      platform: (device && device.platform) || 'unknown',
      active: true,
      createdAt: now,
      updatedAt: now
    });

    // Ensure user-level fields exist
    const userSnap = await userRef.once('value');
    if (!userSnap.exists() || !userSnap.val().createdAt) {
      await userRef.update({
        userId: userId,
        subscribed: true,
        isAnonymous: isAnonymous,
        createdAt: now,
        updatedAt: now,
        lastSeenAt: now
      });
    } else {
      await userRef.update({
        subscribed: true,
        isAnonymous: isAnonymous,
        updatedAt: now,
        lastSeenAt: now
      });
    }

    res.json({
      success: true,
      message: 'Subscription saved successfully',
      subscriptionId: subId,
      anonymous: isAnonymous
    });
  } catch (error) {
    console.error('[subscribe] Error:', error.message);
    res.status(500).json({
      success: false,
      message: 'Unable to save subscription'
    });
  }
});

// ── POST /api/unsubscribe (anonymous + authenticated) ───────────

router.post('/api/unsubscribe', optionalVerifyUser, async (req, res) => {
  try {
    const { endpoint } = req.body;

    if (!endpoint) {
      return res.status(400).json({
        success: false,
        message: 'Subscription endpoint is required'
      });
    }

    const db = dbOrError(res);
    if (!db) return;

    const crypto = require('crypto');
    const subId = crypto
      .createHash('sha256')
      .update(endpoint)
      .digest('hex')
      .slice(0, 24);

    let removed = false;

    if (req.userId) {
      // ── Authenticated user — remove from their subscriptions ──
      const userRef = db.ref('notificationUsers/' + req.userId);
      const subsSnap = await userRef.child('subscriptions').once('value');
      const subs = subsSnap.val() || {};

      for (const [sid, sub] of Object.entries(subs)) {
        if (sub.endpoint === endpoint) {
          await userRef.child('subscriptions/' + sid).update({
            active: false,
            updatedAt: Date.now()
          });
          removed = true;
          break;
        }
      }

      if (removed) {
        const refreshedSnap = await userRef.child('subscriptions').once('value');
        const refreshedSubs = refreshedSnap.val() || {};
        const hasActive = Object.values(refreshedSubs).some(s => s.active === true);
        await userRef.update({
          subscribed: hasActive,
          updatedAt: Date.now()
        });
      }
    } else {
      // ── Anonymous user — find by endpoint hash ──
      const anonRef = db.ref('notificationUsers/anonymous_' + subId);
      const anonSnap = await anonRef.once('value');

      if (anonSnap.exists()) {
        await anonRef.child('subscriptions/' + subId).update({
          active: false,
          updatedAt: Date.now()
        });
        removed = true;

        const refreshedSnap = await anonRef.child('subscriptions').once('value');
        const refreshedSubs = refreshedSnap.val() || {};
        const hasActive = Object.values(refreshedSubs).some(s => s.active === true);
        await anonRef.update({
          subscribed: hasActive,
          updatedAt: Date.now()
        });
      } else {
        // Safety net — search all users for this endpoint
        const allUsersSnap = await db.ref('notificationUsers').once('value');
        const allUsers = allUsersSnap.val() || {};

        outer:
        for (const [uid, udata] of Object.entries(allUsers)) {
          const subs = udata.subscriptions || {};
          for (const [sid, sub] of Object.entries(subs)) {
            if (sub.endpoint === endpoint && sub.active) {
              await db.ref('notificationUsers/' + uid + '/subscriptions/' + sid).update({
                active: false,
                updatedAt: Date.now()
              });
              removed = true;

              const refSnap = await db.ref('notificationUsers/' + uid + '/subscriptions').once('value');
              const refSubs = refSnap.val() || {};
              const hasAct = Object.values(refSubs).some(s => s.active === true);
              await db.ref('notificationUsers/' + uid).update({
                subscribed: hasAct,
                updatedAt: Date.now()
              });
              break outer;
            }
          }
        }
      }
    }

    res.json({
      success: true,
      message: removed ? 'Subscription removed' : 'Subscription not found'
    });
  } catch (error) {
    console.error('[unsubscribe] Error:', error.message);
    res.status(500).json({
      success: false,
      message: 'Unable to remove subscription'
    });
  }
});

// ── GET /api/subscription/status (anonymous + authenticated) ───

router.get('/api/subscription/status', optionalVerifyUser, async (req, res) => {
  try {
    // If user is not authenticated, return subscribed: false.
    // The client checks locally via pushManager.getSubscription()
    // for anonymous users — this is the correct behavior.
    if (!req.userId) {
      return res.json({
        success: true,
        subscribed: false
      });
    }

    const db = dbOrError(res);
    if (!db) return;

    const subscribed = await isUserSubscribed(req.userId);

    res.json({
      success: true,
      subscribed
    });
  } catch (error) {
    console.error('[status] Error:', error.message);
    res.json({
      success: true,
      subscribed: false
    });
  }
});

// ── POST /api/analytics/click ────────────────────────────────────

router.post('/api/analytics/click', async (req, res) => {
  try {
    const { notificationId, event, action } = req.body;

    const validEvents = ['notification_click', 'action_click'];
    if (!validEvents.includes(event)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid event type'
      });
    }

    if (!notificationId) {
      return res.status(400).json({
        success: false,
        message: 'notificationId is required'
      });
    }

    const db = dbOrError(res);
    if (!db) return;

    // Verify the notification exists
    const notifSnap = await db.ref('notifications/' + notificationId).once('value');
    if (!notifSnap.exists()) {
      return res.status(404).json({
        success: false,
        message: 'Notification not found'
      });
    }

    // Rate limit by IP
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const rateKey = 'click:' + ip;
    if (!rateLimit(rateKey, 10, 60000)) {
      return res.status(429).json({
        success: false,
        message: 'Too many requests — please try again later'
      });
    }

    // Record the event
    const eventId = notificationId + '_' + ip + '_' + event + '_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    await db.ref('notificationEvents/' + eventId).set({
      notificationId,
      event,
      action: action || null,
      ip: ip,
      createdAt: Date.now()
    });

    await push.incrementClick(notificationId, event);

    res.json({
      success: true,
      message: 'Click recorded'
    });
  } catch (error) {
    console.error('[analytics/click] Error:', error.message);
    res.status(500).json({
      success: false,
      message: 'Unable to record click'
    });
  }
});

// ═══════════════════════════════════════════════════════════════
//  ADMIN ROUTES (all require x-admin-key header)
// ═══════════════════════════════════════════════════════════════

// ── GET /api/admin/stats ────────────────────────────────────────

router.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const db = dbOrError(res);
    if (!db) return;

    const usersSnap = await db.ref('notificationUsers').once('value');
    const users = usersSnap.val() || {};

    let subscribedUsers = 0;
    let activeDevices = 0;

    for (const userData of Object.values(users)) {
      if (userData.subscribed) subscribedUsers++;
      const subs = userData.subscriptions || {};
      for (const sub of Object.values(subs)) {
        if (sub.active) activeDevices++;
      }
    }

    const notifsSnap = await db.ref('notifications').once('value');
    const notifs = notifsSnap.val() || {};
    const notifList = Object.values(notifs);

    const totalSent = notifList.reduce((sum, n) => sum + (n.sentCount || 0), 0);
    const totalFailed = notifList.reduce((sum, n) => sum + (n.failedCount || 0), 0);
    const totalClicks = notifList.reduce((sum, n) => sum + (n.clickCount || 0), 0);
    const totalActionClicks = notifList.reduce((sum, n) => sum + (n.actionClickCount || 0), 0);

    res.json({
      success: true,
      stats: {
        subscribedUsers,
        activeDevices,
        notificationsSent: notifList.length,
        totalSendAttempts: totalSent,
        totalFailedSends: totalFailed,
        totalNotificationClicks: totalClicks,
        totalActionClicks: totalActionClicks
      }
    });
  } catch (error) {
    console.error('[admin/stats] Error:', error.message);
    res.status(500).json({
      success: false,
      message: 'Unable to fetch stats'
    });
  }
});

// ── GET /api/admin/users ─────────────────────────────────────────

router.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const db = dbOrError(res);
    if (!db) return;

    const usersSnap = await db.ref('notificationUsers').once('value');
    const users = usersSnap.val() || {};

    const userList = Object.entries(users).map(([userId, data]) => {
      const subs = data.subscriptions || {};
      const activeSubs = Object.values(subs).filter(s => s.active);
      return {
        userId,
        subscribed: data.subscribed || false,
        isAnonymous: data.isAnonymous || false,
        deviceCount: activeSubs.length,
        lastSeenAt: data.lastSeenAt || data.updatedAt || null,
        createdAt: data.createdAt || null,
        devices: activeSubs.map(s => ({
          browser: s.browser || s.device || 'unknown',
          platform: s.platform || 'unknown',
          createdAt: s.createdAt,
          active: s.active
        }))
      };
    });

    res.json({
      success: true,
      users: userList
    });
  } catch (error) {
    console.error('[admin/users] Error:', error.message);
    res.status(500).json({
      success: false,
      message: 'Unable to fetch subscribers'
    });
  }
});

// ── GET /api/admin/notifications ───────────────────────────────

router.get('/api/admin/notifications', requireAdmin, async (req, res) => {
  try {
    const db = dbOrError(res);
    if (!db) return;

    const notifsSnap = await db.ref('notifications').once('value');
    const notifs = notifsSnap.val() || {};

    const notifList = Object.entries(notifs)
      .map(([id, data]) => ({
        id,
        title: data.title,
        body: data.body,
        type: data.type,
        audience: data.audience,
        targetUserId: data.targetUserId || null,
        sentCount: data.sentCount || 0,
        failedCount: data.failedCount || 0,
        removedCount: data.removedCount || 0,
        clickCount: data.clickCount || 0,
        actionClickCount: data.actionClickCount || 0,
        status: data.status || 'pending',
        createdAt: data.createdAt || 0,
        actionText: data.actionText || null,
        destinationUrl: data.destinationUrl || null,
        imageUrl: data.imageUrl || null
      }))
      .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

    res.json({
      success: true,
      notifications: notifList
    });
  } catch (error) {
    console.error('[admin/notifications] Error:', error.message);
    res.status(500).json({
      success: false,
      message: 'Unable to fetch notifications'
    });
  }
});

// ── POST /api/admin/send (broadcast) ───────────────────────────

router.post('/api/admin/send', requireAdmin, async (req, res) => {
  try {
    const {
      title,
      body,
      imageUrl,
      iconUrl,
      badgeUrl,
      actionText,
      destinationUrl,
      type,
      audience
    } = req.body;

    if (!title || !body) {
      return res.status(400).json({
        success: false,
        message: 'Title and message body are required'
      });
    }

    if (audience !== 'all') {
      return res.status(400).json({
        success: false,
        message: 'Use /api/admin/send-user for specific user targeting'
      });
    }

    if (imageUrl && !isValidUrl(imageUrl)) {
      return res.status(400).json({ success: false, message: 'Invalid image URL' });
    }
    if (iconUrl && !isValidUrl(iconUrl)) {
      return res.status(400).json({ success: false, message: 'Invalid icon URL' });
    }
    if (badgeUrl && !isValidUrl(badgeUrl)) {
      return res.status(400).json({ success: false, message: 'Invalid badge URL' });
    }
    if (destinationUrl && !isValidUrl(destinationUrl)) {
      return res.status(400).json({ success: false, message: 'Invalid destination URL' });
    }

    const notificationId = 'notif_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    const now = Date.now();

    const notification = {
      id: notificationId,
      title,
      body,
      type: type || 'general',
      imageUrl: imageUrl || null,
      iconUrl: iconUrl || null,
      badgeUrl: badgeUrl || null,
      actionText: actionText || null,
      destinationUrl: destinationUrl || 'https://smmaria.site',
      audience: 'all',
      createdAt: now,
      createdBy: 'admin',
      status: 'sending',
      sentCount: 0,
      failedCount: 0,
      removedCount: 0,
      clickCount: 0,
      actionClickCount: 0
    };

    await push.saveNotification(notification);

    const stats = await push.broadcast(notification);

    await push.updateNotificationStats(notificationId, stats);

    res.json({
      success: true,
      message: 'Notification broadcast complete',
      notificationId,
      stats
    });
  } catch (error) {
    console.error('[admin/send] Error:', error.message);
    res.status(500).json({
      success: false,
      message: 'Unable to send notification'
    });
  }
});

// ── POST /api/admin/send-user (specific user) ──────────────────

router.post('/api/admin/send-user', requireAdmin, async (req, res) => {
  try {
    const {
      title,
      body,
      imageUrl,
      iconUrl,
      badgeUrl,
      actionText,
      destinationUrl,
      type,
      targetUserId
    } = req.body;

    if (!title || !body) {
      return res.status(400).json({
        success: false,
        message: 'Title and message body are required'
      });
    }

    if (!targetUserId) {
      return res.status(400).json({
        success: false,
        message: 'targetUserId is required for specific user sends'
      });
    }

    if (imageUrl && !isValidUrl(imageUrl)) {
      return res.status(400).json({ success: false, message: 'Invalid image URL' });
    }
    if (iconUrl && !isValidUrl(iconUrl)) {
      return res.status(400).json({ success: false, message: 'Invalid icon URL' });
    }
    if (destinationUrl && !isValidUrl(destinationUrl)) {
      return res.status(400).json({ success: false, message: 'Invalid destination URL' });
    }

    const notificationId = 'notif_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    const now = Date.now();

    const notification = {
      id: notificationId,
      title,
      body,
      type: type || 'general',
      imageUrl: imageUrl || null,
      iconUrl: iconUrl || null,
      badgeUrl: badgeUrl || null,
      actionText: actionText || null,
      destinationUrl: destinationUrl || 'https://smmaria.site',
      audience: 'specific',
      targetUserId,
      createdAt: now,
      createdBy: 'admin',
      status: 'sending',
      sentCount: 0,
      failedCount: 0,
      removedCount: 0,
      clickCount: 0,
      actionClickCount: 0
    };

    await push.saveNotification(notification);

    const stats = await push.sendToUser(targetUserId, notification);

    await push.updateNotificationStats(notificationId, stats);

    res.json({
      success: true,
      message: 'Notification sent to user',
      notificationId,
      stats
    });
  } catch (error) {
    console.error('[admin/send-user] Error:', error.message);
    res.status(500).json({
      success: false,
      message: 'Unable to send notification to user'
    });
  }
});

// ── GET /api/admin/analytics/:notificationId ───────────────────

router.get('/api/admin/analytics/:notificationId', requireAdmin, async (req, res) => {
  try {
    const { notificationId } = req.params;
    const db = dbOrError(res);
    if (!db) return;

    const notifSnap = await db.ref('notifications/' + notificationId).once('value');
    if (!notifSnap.exists()) {
      return res.status(404).json({
        success: false,
        message: 'Notification not found'
      });
    }

    const analyticsSnap = await db.ref('notificationAnalytics/' + notificationId).once('value');
    const analytics = analyticsSnap.val() || {};

    const notif = notifSnap.val();

    res.json({
      success: true,
      analytics: {
        notificationId,
        title: notif.title,
        body: notif.body,
        type: notif.type,
        audience: notif.audience,
        targetUserId: notif.targetUserId || null,
        actionText: notif.actionText || null,
        destinationUrl: notif.destinationUrl || null,
        imageUrl: notif.imageUrl || null,
        iconUrl: notif.iconUrl || null,
        status: notif.status || 'unknown',
        createdAt: notif.createdAt || null,
        sentCount: analytics.sentCount || notif.sentCount || 0,
        failedCount: analytics.failedCount || notif.failedCount || 0,
        removedCount: analytics.removedCount || notif.removedCount || 0,
        clickCount: analytics.clickCount || notif.clickCount || 0,
        actionClickCount: analytics.actionClickCount || notif.actionClickCount || 0,
        uniqueClickCount: analytics.uniqueClickCount || 0
      }
    });
  } catch (error) {
    console.error('[admin/analytics] Error:', error.message);
    res.status(500).json({
      success: false,
      message: 'Unable to fetch analytics'
    });
  }
});

module.exports = router;
