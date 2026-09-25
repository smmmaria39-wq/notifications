/**
 * SMMARIA NOTIFICATIONS — Firebase Initialization
 * Connects to Firebase Realtime Database using Admin SDK.
 * Uses ONLY notification-specific nodes. Never touches
 * wallets/, orders/, payments/, services/, campaigns/.
 */

const admin = require('firebase-admin');

let db = null;
let initialized = false;

function initFirebase() {
 if (initialized) return db;
 
 const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT;
 const databaseUrl = process.env.FIREBASE_DATABASE_URL;
 
 if (!serviceAccountJson || !databaseUrl) {
  console.warn(
   '[firebase] FIREBASE_SERVICE_ACCOUNT or FIREBASE_DATABASE_URL not set. ' +
   'Notification storage will not persist. Set these in Railway variables.'
  );
  return null;
 }
 
 try {
  const serviceAccount = JSON.parse(serviceAccountAccountJson || serviceAccountJson);
  
  admin.initializeApp({
   credential: admin.credential.cert(serviceAccount),
   databaseURL: databaseUrl
  });
  
  db = admin.database();
  initialized = true;
  console.log('[firebase] Connected to Firebase Realtime Database');
  return db;
 } catch (error) {
  console.error('[firebase] Initialization failed:', error.message);
  return null;
 }
}

/** Safe getter — returns the db ref or null if Firebase is unavailable */
function getDb() {
 if (!initialized) initFirebase();
 return db;
}

/** Check if Firebase is available */
function isAvailable() {
 return getDb() !== null;
}

module.exports = {
 initFirebase,
 getDb,
 isAvailable,
 admin
};