/**
 * backend/index.js
 * Complete server file — drop this into your backend folder as index.js
 *
 * Fixes:
 * - Ensures `app` is defined before any routes are declared.
 * - Provides authenticateToken middleware and routes (reviews/posts/TMDb proxy).
 * - Safer owner checks with String(...) comparisons and optional ADMIN_EMAILS override.
 * - Debug endpoint to inspect a post document.
 *
 * Run with:
 *   node index.js
 *
 * Make sure this file is NOT inside your React `src/` folder.
 */

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const admin = require('firebase-admin');
const dotenv = require('dotenv');
const fs = require('fs');
const path = require('path');

dotenv.config();

const PORT = process.env.PORT || 5000;
const TMDB_API_KEY = process.env.TMDB_API_KEY;
const SERVICE_ACCOUNT_PATH = process.env.FIREBASE_SERVICE_ACCOUNT_PATH || './firebase-service-account.json';
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || '*';

// Basic checks
if (!TMDB_API_KEY) {
  console.error('Error: TMDB_API_KEY is not set in .env');
  process.exit(1);
}

try {
  const serviceAccountPath = path.resolve(SERVICE_ACCOUNT_PATH);
  if (!fs.existsSync(serviceAccountPath)) {
    console.error(`Firebase service account JSON not found at ${serviceAccountPath}`);
    console.error('Place the downloaded service account JSON in the backend folder and set FIREBASE_SERVICE_ACCOUNT_PATH in .env accordingly.');
    process.exit(1);
  }
  const serviceAccount = require(serviceAccountPath);
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
} catch (err) {
  console.error('Failed to initialize Firebase Admin:', err);
  process.exit(1);
}

const db = admin.firestore();

// Create app BEFORE declaring routes (this fixed your "app is not defined" error)
const app = express();

// Simple request logger
app.use((req, res, next) => {
  console.log(new Date().toISOString(), req.method, req.url, 'origin:', req.headers.origin, 'hasAuthHeader:', !!req.headers.authorization);
  next();
});

app.use(express.json());
app.use(cors({
  origin: FRONTEND_ORIGIN,
  optionsSuccessStatus: 200
}));

// Auth middleware
async function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;
  if (!token) {
    console.warn('No token provided for', req.method, req.url);
    return res.status(401).json({ message: 'No token provided' });
  }
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    console.log('Token decoded uid=', decoded.uid, 'email=', decoded.email);
    req.user = { uid: decoded.uid, email: decoded.email };
    next();
  } catch (err) {
    console.error('Token verification error', err);
    return res.status(401).json({ message: 'Invalid token', error: err.message });
  }
}

/* ------------------ TMDb proxy routes ------------------ */
app.get('/api/search', async (req, res) => {
  const q = req.query.q;
  if (!q) return res.status(400).json({ message: 'Missing query param q' });
  try {
    const tmdbRes = await axios.get('https://api.themoviedb.org/3/search/movie', {
      params: {
        api_key: TMDB_API_KEY,
        query: q,
        include_adult: false,
        page: req.query.page || 1
      }
    });
    res.json(tmdbRes.data);
  } catch (err) {
    console.error('TMDb search error', err.response ? err.response.data : err.message);
    res.status(500).json({ message: 'TMDb search failed', error: err.response ? err.response.data : err.message });
  }
});

app.get('/api/movie/:id', async (req, res) => {
  const id = req.params.id;
  try {
    const tmdbRes = await axios.get(`https://api.themoviedb.org/3/movie/${id}`, {
      params: { api_key: TMDB_API_KEY }
    });
    res.json(tmdbRes.data);
  } catch (err) {
    console.error('TMDb movie fetch error', err.response ? err.response.data : err.message);
    res.status(500).json({ message: 'TMDb movie fetch failed', error: err.response ? err.response.data : err.message });
  }
});

app.get('/api/popular', async (req, res) => {
  try {
    const page = req.query.page || 1;
    const tmdbRes = await axios.get('https://api.themoviedb.org/3/movie/popular', {
      params: {
        api_key: TMDB_API_KEY,
        page
      }
    });
    res.json(tmdbRes.data);
  } catch (err) {
    console.error('TMDb popular fetch error', err.response ? err.response.data : err.message);
    res.status(500).json({ message: 'TMDb popular fetch failed', error: err.response ? err.response.data : err.message });
  }
});

/* ------------------ Reviews ------------------ */
app.get('/api/reviews/movie/:movieId', async (req, res) => {
  const movieId = req.params.movieId;
  try {
    const snapshot = await db.collection('reviews')
      .where('movieId', '==', movieId)
      .get();

    const reviews = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    reviews.sort((a, b) => {
      const aTs = a.createdAt && typeof a.createdAt.toMillis === 'function' ? a.createdAt.toMillis() : 0;
      const bTs = b.createdAt && typeof b.createdAt.toMillis === 'function' ? b.createdAt.toMillis() : 0;
      return bTs - aTs;
    });

    res.json(reviews);
  } catch (err) {
    console.error('Failed to fetch reviews', err);
    res.status(500).json({ message: 'Failed to fetch reviews', error: err.message });
  }
});

app.post('/api/reviews', authenticateToken, async (req, res) => {
  const { movieId, movieTitle, rating, text } = req.body;
  if (!movieId || rating === undefined) return res.status(400).json({ message: 'movieId and rating required' });
  try {
    const now = admin.firestore.FieldValue.serverTimestamp();
    const docRef = await db.collection('reviews').add({
      movieId,
      movieTitle: movieTitle || '',
      rating,
      text: text || '',
      uid: req.user.uid,
      userEmail: req.user.email || '',
      createdAt: now,
      updatedAt: now
    });
    const doc = await docRef.get();
    res.status(201).json({ id: docRef.id, ...doc.data() });
  } catch (err) {
    console.error('Failed to create review', err);
    res.status(500).json({ message: 'Failed to create review', error: err.message });
  }
});

// Safer uid comparison for reviews
app.put('/api/reviews/:id', authenticateToken, async (req, res) => {
  const id = req.params.id;
  const { rating, text } = req.body;
  try {
    console.log('Update review request by uid=', req.user.uid, 'for review id=', id);
    const docRef = db.collection('reviews').doc(id);
    const doc = await docRef.get();
    if (!doc.exists) return res.status(404).json({ message: 'Review not found' });
    const data = doc.data();

    if (String(data.uid) !== String(req.user.uid)) {
      console.warn('Unauthorized review update: reviewOwner=', data.uid, 'requester=', req.user.uid);
      return res.status(403).json({ message: 'Not authorized' });
    }

    await docRef.update({
      rating: rating !== undefined ? rating : data.rating,
      text: text !== undefined ? text : data.text,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });
    const updated = await docRef.get();
    res.json({ id: updated.id, ...updated.data() });
  } catch (err) {
    console.error('Failed to update review', err);
    res.status(500).json({ message: 'Failed to update review', error: err.message });
  }
});

app.delete('/api/reviews/:id', authenticateToken, async (req, res) => {
  const id = req.params.id;
  try {
    console.log('Delete review request by uid=', req.user.uid, 'for review id=', id);
    const docRef = db.collection('reviews').doc(id);
    const doc = await docRef.get();
    if (!doc.exists) return res.status(404).json({ message: 'Review not found' });
    const data = doc.data();

    if (String(data.uid) !== String(req.user.uid)) {
      console.warn('Unauthorized review delete: reviewOwner=', data.uid, 'requester=', req.user.uid);
      return res.status(403).json({ message: 'Not authorized' });
    }

    await docRef.delete();
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error('Failed to delete review', err);
    res.status(500).json({ message: 'Failed to delete review', error: err.message });
  }
});

app.get('/api/my-reviews', authenticateToken, async (req, res) => {
  try {
    const snapshot = await db.collection('reviews')
      .where('uid', '==', req.user.uid)
      .get();

    const reviews = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    reviews.sort((a, b) => {
      const aTs = a.createdAt && typeof a.createdAt.toMillis === 'function' ? a.createdAt.toMillis() : 0;
      const bTs = b.createdAt && typeof b.createdAt.toMillis === 'function' ? b.createdAt.toMillis() : 0;
      return bTs - aTs;
    });

    res.json(reviews);
  } catch (err) {
    console.error('Failed to fetch my reviews', err.stack || err);
    res.status(500).json({ message: 'Failed to fetch my reviews', error: err.message });
  }
});

/* ------------------ Posts ------------------ */
app.get('/api/posts', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit || '5', 10);
    const snapshot = await db.collection('posts')
      .orderBy('createdAt', 'desc')
      .limit(limit)
      .get();
    const posts = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
    res.json(posts);
  } catch (err) {
    console.error('Failed to fetch posts', err);
    res.status(500).json({ message: 'Failed to fetch posts', error: err.message });
  }
});

app.post('/api/posts', authenticateToken, async (req, res) => {
  try {
    const { title, excerpt, content } = req.body;
    if (!title) return res.status(400).json({ message: 'title required' });
    const now = admin.firestore.FieldValue.serverTimestamp();
    const docRef = await db.collection('posts').add({
      title,
      excerpt: excerpt || '',
      content: content || '',
      authorUid: req.user.uid,
      authorEmail: req.user.email || '',
      createdAt: now,
      updatedAt: now
    });
    const doc = await docRef.get();
    res.status(201).json({ id: docRef.id, ...doc.data() });
  } catch (err) {
    console.error('Failed to create post', err);
    res.status(500).json({ message: 'Failed to create post', error: err.message });
  }
});

// Helper: owner/admin check
function isOwnerOrAdmin(docData, reqUser) {
  const authorUid = docData?.authorUid;
  const authorEmail = docData?.authorEmail || docData?.userEmail || '';
  const requesterUid = reqUser?.uid;
  const requesterEmail = reqUser?.email || '';

  const adminEmails = (process.env.ADMIN_EMAILS || '').split(',').map(s => s.trim()).filter(Boolean);
  const isAdmin = adminEmails.length > 0 && adminEmails.includes(requesterEmail);

  const sameUid = authorUid !== undefined && String(authorUid) === String(requesterUid);
  const sameEmail = authorEmail && String(authorEmail).toLowerCase() === String(requesterEmail).toLowerCase();

  return isAdmin || sameUid || sameEmail;
}

// PUT - update post (owner/admin)
app.put('/api/posts/:id', authenticateToken, async (req, res) => {
  const id = req.params.id;
  const { title, excerpt, content } = req.body;
  try {
    console.log('Update post request by uid=', req.user?.uid, 'email=', req.user?.email, 'for post id=', id);
    const docRef = db.collection('posts').doc(id);
    const doc = await docRef.get();
    if (!doc.exists) {
      console.warn('Update failed: post not found', id);
      return res.status(404).json({ message: 'Post not found' });
    }
    const data = doc.data();

    if (!isOwnerOrAdmin(data, req.user)) {
      console.warn('Unauthorized post update: authorUid=', data?.authorUid, 'authorEmail=', data?.authorEmail, 'requester=', req.user);
      return res.status(403).json({ message: 'Not authorized to edit this post' });
    }

    await docRef.update({
      title: title !== undefined ? title : data.title,
      excerpt: excerpt !== undefined ? excerpt : data.excerpt,
      content: content !== undefined ? content : data.content,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    const updated = await docRef.get();
    res.json({ id: updated.id, ...updated.data() });
  } catch (err) {
    console.error('Failed to update post', err);
    res.status(500).json({ message: 'Failed to update post', error: err.message });
  }
});

// PATCH - partial update (owner/admin)
app.patch('/api/posts/:id', authenticateToken, async (req, res) => {
  const id = req.params.id;
  const updates = {};
  if (req.body.title !== undefined) updates.title = req.body.title;
  if (req.body.excerpt !== undefined) updates.excerpt = req.body.excerpt;
  if (req.body.content !== undefined) updates.content = req.body.content;

  if (Object.keys(updates).length === 0) {
    return res.status(400).json({ message: 'No fields to update' });
  }

  updates.updatedAt = admin.firestore.FieldValue.serverTimestamp();

  try {
    console.log('Patch post request by uid=', req.user?.uid, 'email=', req.user?.email, 'for post id=', id, 'updates=', Object.keys(updates));
    const docRef = db.collection('posts').doc(id);
    const doc = await docRef.get();
    if (!doc.exists) return res.status(404).json({ message: 'Post not found' });
    const data = doc.data();

    if (!isOwnerOrAdmin(data, req.user)) {
      console.warn('Unauthorized post patch: authorUid=', data?.authorUid, 'authorEmail=', data?.authorEmail, 'requester=', req.user);
      return res.status(403).json({ message: 'Not authorized to edit this post' });
    }

    await docRef.update(updates);
    const updated = await docRef.get();
    res.json({ id: updated.id, ...updated.data() });
  } catch (err) {
    console.error('Failed to patch post', err);
    res.status(500).json({ message: 'Failed to patch post', error: err.message });
  }
});

// DELETE - delete post (owner/admin)
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
  const id = req.params.id;
  try {
    console.log('Delete post request by uid=', req.user?.uid, 'email=', req.user?.email, 'for post id=', id);
    const docRef = db.collection('posts').doc(id);
    const doc = await docRef.get();
    if (!doc.exists) {
      console.warn('Delete failed: post not found', id);
      return res.status(404).json({ message: 'Post not found' });
    }
    const data = doc.data();

    if (!isOwnerOrAdmin(data, req.user)) {
      console.warn('Unauthorized post delete: authorUid=', data?.authorUid, 'authorEmail=', data?.authorEmail, 'requester=', req.user);
      return res.status(403).json({ message: 'Not authorized to delete this post' });
    }

    await docRef.delete();
    console.log('Post deleted:', id, 'by', req.user?.uid);
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error('Failed to delete post', err);
    res.status(500).json({ message: 'Failed to delete post', error: err.message });
  }
});

/* Debug endpoint to inspect a post document - REMOVE in production if desired */
app.get('/api/debug/posts/:id', async (req, res) => {
  try {
    const doc = await db.collection('posts').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ message: 'Post not found' });
    return res.json({ id: doc.id, data: doc.data() });
  } catch (err) {
    console.error('Debug fetch failed', err);
    return res.status(500).json({ message: 'Debug fetch failed', error: err.message });
  }
});

/* Fetch single post (non-auth) */
app.get('/api/posts/:id', async (req, res) => {
  try {
    const doc = await db.collection('posts').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ message: 'Post not found' });
    res.json({ id: doc.id, ...doc.data() });
  } catch (err) {
    console.error('Failed to fetch post', err);
    res.status(500).json({ message: 'Failed to fetch post', error: err.message });
  }
});

/* Root */
app.get('/', (req, res) => res.send('Movie Review Backend is running'));

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});