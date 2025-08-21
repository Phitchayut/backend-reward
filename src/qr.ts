import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import { pool, nowSec } from './db';
import jwt from 'jsonwebtoken';

const STORE_ID = process.env.STORE_ID || 'EYELASH_001';
const QR_TTL_SECONDS = parseInt(process.env.QR_TTL_SECONDS || '60', 10);
const MIN_INTERVAL_SECONDS = parseInt(process.env.MIN_INTERVAL_SECONDS || '60', 10);
const signSecret = process.env.SESSION_SECRET || 'dev_secret';
const JWT_SECRET = process.env.JWT_SECRET!;
const hmac = (payload: string) => crypto.createHmac('sha256', signSecret).update(payload).digest('hex');

// รองรับทั้ง Bearer token และ session ของ passport
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  // 1) ลองอ่านจาก Authorization: Bearer <token>
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';

  if (token) {
    try {
      const payload = jwt.verify(token, JWT_SECRET) as any;
      // แนบ payload ไว้ที่ req.user เพื่อให้ downstream ใช้ต่อได้
      (req as any).user = payload;
      return next();
    } catch {
      // token ผิด/หมดอายุ → ตกไปเช็ค session ต่อ
    }
  }

  // 2) fallback: session (เผื่อบางอุปกรณ์/เดสก์ท็อปยังส่ง cookie มาได้)
  const authed = (req as any).isAuthenticated && (req as any).isAuthenticated();
  if (authed && (req as any).user) return next();

  return res.status(401).json({ error: 'Unauthorized' });
}

// GET /api/qr?storeId=EYELASH_001
export async function getQr(req: Request, res: Response) {
  const storeId = (req.query.storeId as string) || STORE_ID;
  const exp = nowSec() + QR_TTL_SECONDS;
  const nonce = crypto.randomBytes(6).toString('hex');
  const code = hmac(`${storeId}.${exp}.${nonce}`);

  await pool.query(
    `INSERT INTO otc (code, store_id, exp, used, created_at)
     VALUES ($1,$2,$3,false,$4)
     ON CONFLICT (code) DO UPDATE SET exp=EXCLUDED.exp, used=false, created_at=EXCLUDED.created_at`,
    [code, storeId, exp, nowSec()]
  );

  res.json({ code, storeId, exp });
}

// POST /api/redeem { code }
export async function postRedeem(req: Request, res: Response) {
  const user = (req as any).user as any;
  const { code } = req.body as { code: string };
  if (!code) return res.status(400).json({ error: 'Missing code' });

  const { rows } = await pool.query('SELECT * FROM otc WHERE code=$1', [code]);
  const otc = rows[0];
  if (!otc) return res.status(403).json({ error: 'Invalid or expired QR' });
  if (otc.used) return res.status(409).json({ error: 'QR already used' });
  if (otc.exp < nowSec()) return res.status(410).json({ error: 'QR expired' });

  const uRes = await pool.query('SELECT * FROM users WHERE id=$1', [user.id]);
  const u = uRes.rows[0];
let lastSec = 0;
if (u?.updated_at != null) {
  if (typeof u.updated_at === 'number') {
    // ถ้าเป็นมิลลิวินาที (13 หลัก) แปลงเป็นวินาที
    lastSec = u.updated_at > 1e12 ? Math.floor(u.updated_at / 1000) : u.updated_at;
  } else {
    // ถ้าเป็น string/Date (timestamp) แปลงเป็นวินาที
    lastSec = Math.floor(new Date(u.updated_at).getTime() / 1000);
  }
}

if (nowSec() - lastSec < MIN_INTERVAL_SECONDS) {
  return res.status(429).json({ error: 'Please wait before scanning again.' });
}

  const current = u?.stamp_count ?? 0;
  const next = (current + 1) % 8;
  const reward = next === 0;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('UPDATE otc SET used=true, used_by=$1, used_at=$2 WHERE code=$3', [user.id, nowSec(), code]);
    await client.query(
      `UPDATE users
         SET stamp_count=$1,
             updated_at=$2,
             last_redeemed_at = CASE WHEN $3 THEN $2 ELSE last_redeemed_at END
       WHERE id=$4`,
      [next, nowSec(), reward, user.id]
    );
    if (reward) {
      await client.query('INSERT INTO redeem_logs (uid, store_id, at) VALUES ($1,$2,$3)', [user.id, otc.store_id, nowSec()]);
    }
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }

  return res.json({ next, reward });
}
