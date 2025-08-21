import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import passport from './auth';
import { getQr, postRedeem, requireAuth } from './qr';
import path from 'path';
import { pool } from './db';
import deletionRouter from './deletion';
import jwt from 'jsonwebtoken';

const app = express();
const PgSession = connectPgSimple(session);

const IS_PROD = process.env.NODE_ENV === 'production';
const PORT = parseInt(process.env.PORT || (IS_PROD ? '10000' : '4000'), 10);

// ✅ ควรเป็น origin แบบ “ไม่มี / ท้าย”
const FRONTEND = (process.env.CLIENT_ORIGIN || 'https://goodmorning-lash-studio.netlify.app').replace(/\/$/, '');

// ✅ สำคัญ: อยู่หลัง proxy (Render/Heroku ฯลฯ)
app.set('trust proxy', 1);

// ---------- CORS ----------
app.use(cors({
  origin: (origin, cb) => {
    // อนุญาต request ที่ไม่มี Origin (เช่น curl/health check)
    if (!origin) return cb(null, true);
    const allowlist = new Set([FRONTEND]);
    if (allowlist.has(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
}));
// ให้ cache แยกตาม origin
app.use((_, res, next) => { res.header('Vary', 'Origin'); next(); });

// ---------- Parsers ----------
app.use(express.json());

// ---------- Session ----------
app.use(session({
  store: new PgSession({
    pool,
    tableName: 'session',
    createTableIfMissing: true,
  }),
  secret: process.env.SESSION_SECRET || 'dev_secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    // ✅ Cross-site cookie ต้องเป็น secure + sameSite:'none'
    secure: IS_PROD,           // Render คือ HTTPS -> true
    sameSite: IS_PROD ? 'none' : 'lax', // dev local ยังปล่อย lax ได้
    maxAge: 7 * 24 * 3600 * 1000,
  },
}));

// ---------- Passport ----------
app.use(passport.initialize());
app.use(passport.session());

// ---------- Static (store-qr.html) ----------
app.use(express.static(path.join(__dirname, '../public')));

function signUserJWT(user: any) {
  const payload = {
    id: user.id,
    displayName: user.display_name,
    photo: user.photo,
    stampCount: user.stamp_count,
  };
  return jwt.sign(payload, process.env.JWT_SECRET!, { expiresIn: '2h' });
}

// ---------- Auth ----------
app.get('/auth/facebook',
  passport.authenticate('facebook', { scope: ['email'] })
);


// ✅ หลัง login สำเร็จ: ออก JWT แล้วแนบกลับทาง hash
app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: `${FRONTEND}/?login=failed` }),
  (req, res) => {
    const token = signUserJWT((req as any).user);
    return res.redirect(`${FRONTEND}/?login=success#token=${encodeURIComponent(token)}`);
  }
);

// ✅ /auth/status: รองรับ Bearer ก่อน แล้วค่อย fallback เป็น session
app.get('/auth/status', async (req, res) => {
  const JWT_SECRET = process.env.JWT_SECRET!;
  let uid: number | string | undefined;

  // 1) ดึง id จาก Bearer token ก่อน
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (token) {
    try {
      const p: any = jwt.verify(token, JWT_SECRET);
      uid = p.id;                 // ✅ ใช้เฉพาะ id จาก token
    } catch {/* ignore and fallback */}
  }

  // 2) fallback: session (กรณีบางเครื่องยังใช้ cookie ได้)
  if (!uid && (req as any).isAuthenticated?.()) {
    uid = (req as any).user?.id;
  }

  if (!uid) return res.status(401).json({ loggedIn: false });

  // 3) อ่าน “ค่าปัจจุบัน” จาก DB เสมอ
  const { rows } = await pool.query(
    `SELECT id, display_name AS "displayName", photo, stamp_count AS "stampCount"
     FROM users WHERE id=$1`,
    [uid]
  );
  if (!rows.length) return res.status(401).json({ loggedIn: false });

  return res.json({ loggedIn: true, user: rows[0] });
});

app.post('/auth/logout', (req, res, next) => {
  (req as any).logout((err: any) => {
    if (err) return next(err);
    // ทำลาย session ใน store ด้วย (optional)
    req.session?.destroy(() => {
      res.clearCookie('connect.sid', {
        httpOnly: true,
        secure: IS_PROD,
        sameSite: IS_PROD ? 'none' : 'lax',
      });
      res.json({ ok: true });
    });
  });
});

// ---------- APIs ----------
app.get('/api/qr', getQr);
app.post('/api/redeem', requireAuth, postRedeem);

// ---------- Deletion (optional) ----------
app.use('/', deletionRouter);

// ---------- Health ----------
app.get('/healthz', (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log('Server on :' + PORT));
