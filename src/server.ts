import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import passport from './auth';
import { getQr, postRedeem, requireAuth } from './qr';
import path from 'path';
import { pool } from './db';
import deletionRouter from './deletion'; // ถ้าไม่ใช้ลบข้อมูลให้ลบบรรทัดนี้ทิ้ง

const app = express();
const PgSession = connectPgSimple(session);

const IS_PROD = process.env.NODE_ENV === 'production';
const PORT = parseInt(process.env.PORT || (IS_PROD ? '10000' : '4000'), 10);
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:5173';
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev_secret';

app.use(cors({ origin: CLIENT_ORIGIN, credentials: true }));
app.use(express.json());

app.use(session({
  store: new PgSession({
    pool,
    tableName: 'session',
    createTableIfMissing: true
  }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    sameSite: 'lax',
    secure: IS_PROD,              // Render (HTTPS) = true, local dev = false
    maxAge: 7 * 24 * 3600 * 1000
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// Static (store-qr.html)
app.use(express.static(path.join(__dirname, '../public')));

// Auth routes
app.get('/auth/facebook', passport.authenticate('facebook'));
app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: CLIENT_ORIGIN + '/?login=failed' }),
  (_req, res) => res.redirect(CLIENT_ORIGIN + '/?login=success')
);
app.get('/auth/status', (req, res) => {
  const isAuth = (req as any).isAuthenticated && (req as any).isAuthenticated();
  if (isAuth) {
    const u = (req as any).user;
    return res.json({ loggedIn: true, user: { id: u.id, displayName: u.display_name, photo: u.photo, stampCount: u.stamp_count } });
  }
  res.json({ loggedIn: false });
});
app.post('/auth/logout', (req, res, next) => {
  (req as any).logout((err: any) => err ? next(err) : res.json({ ok: true }));
});

// APIs
app.get('/api/qr', getQr);
app.post('/api/redeem', requireAuth, postRedeem);

// (ออปชัน) Data deletion endpoint
app.use('/', deletionRouter);

// Health
app.get('/healthz', (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log('Server on :' + PORT));
