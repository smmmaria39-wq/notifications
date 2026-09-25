/**
 * SMMARIA NOTIFICATIONS — Firebase Initialization
 */

const admin = require('firebase-admin');

let db = null;
let initialized = false;

function initFirebase() {
  if (initialized) return db;

  const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
  const databaseUrl = process.env.FIREBASE_DATABASE_URL;

  if (!raw || !databaseUrl) {
    console.warn(
      '[firebase] FIREBASE_SERVICE_ACCOUNT or FIREBASE_DATABASE_URL not set. ' +
      'Notification storage will not persist. Set these in Railway variables.'
    );
    return null;
  }

  // Debug: show what we actually received from Railway
  console.log('[firebase] Service account string length:', raw.length);
  console.log('[firebase] First 40 chars:', raw.substring(0, 40));
  console.log('[firebase] Last 40 chars:', raw.substring(raw.length - 40));

  let serviceAccount;

  try {
    // Attempt 1: Direct JSON parse
    serviceAccount = JSON.parse(raw);
    console.log('[firebase] Parsed JSON directly');
  } catch (e1) {
    console.warn('[firebase] Direct parse failed:', e1.message);

    try {
      // Attempt 2: Maybe it was base64 encoded
      const decoded = Buffer.from(raw, 'base64').toString('utf8');
      serviceAccount = JSON.parse(decoded);
      console.log('[firebase] Parsed via base64 decode');
    } catch (e2) {
      // Attempt 3: Try to fix broken newlines in private_key
      try {
        // Sometimes Railway converts \n to actual newlines inside the
        // private_key string, breaking the JSON. Try replacing actual
        // newlines that appear between quotes with \n escape sequences.
        let fixed = raw
          .replace(/\r\n/g, '\n')
          .replace(/\n/g, '\\n')
          .replace(/\\n\\n/g, '\\n')
          .replace(/\\n-----END/g, '\\n-----END')
          .replace(/\\n"/g, '\\n"');

        // This is fragile, so also try the original approach
        // of just removing all whitespace outside of quotes
        serviceAccount = JSON.parse(raw.trim());
        console.log('[firebase] Parsed after trim');
      } catch (e3) {
        console.error('[firebase] All parse attempts failed.');
        console.error('[firebase] The FIREBASE_SERVICE_ACCOUNT variable is not valid JSON.');
        console.error('[firebase] Length received:', raw.length, 'characters');
        console.error('[firebase] It should start with: {"type":"service_account"');
        console.error('[firebase] It should end with: }');
        return null;
      }
    }
  }

  try {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL: databaseUrl
    });

    db = admin.database();
    initialized = true;
    console.log('[firebase] Connected to Firebase Realtime Database');
    return db;
  } catch (error) {
    console.error('[firebase] Admin SDK init failed:', error.message);
    return null;
  }
}

function getDb() {
  if (!initialized) initFirebase();
  return db;
}

function isAvailable() {
  return getDb() !== null;
}

module.exports = {
  initFirebase,
  getDb,
  isAvailable,
  admin
};
