// src/deletion.ts
import express from 'express';
import crypto from 'crypto';
import { pool } from './db';

const router = express.Router();

// ✅ ต้องรองรับ application/x-www-form-urlencoded เพราะ Facebook จะส่งแบบนี้
router.use(express.urlencoded({ extended: false }));

// ---------- 1) Data Deletion Callback (Facebook เรียก POST พร้อม signed_request) ----------
router.post('/facebook/deletion', async (req, res) => {
  try {
    const signed = req.body.signed_request as string | undefined;
    if (!signed) return res.status(400).send('missing signed_request');

    // แยก signature กับ payload (base64url)
    const [encodedSig, encodedPayload] = signed.split('.');
    if (!encodedSig || !encodedPayload) return res.status(400).send('invalid signed_request');

    const sigBuf = b64urlToBuf(encodedSig);
    const payloadBuf = b64urlToBuf(encodedPayload);

    // ตรวจ HMAC-SHA256 ด้วย App Secret
    const appSecret = process.env.FB_APP_SECRET!;
    const expected = crypto
      .createHmac('sha256', appSecret)
      .update(encodedPayload)
      .digest();

    if (!crypto.timingSafeEqual(sigBuf, expected)) {
      return res.status(400).send('invalid signature');
    }

    // payload จะมี user_id, issued_at, และอื่น ๆ
    const payload = JSON.parse(payloadBuf.toString('utf8'));
    const userId = payload.user_id as string | undefined;
    if (!userId) return res.status(400).send('no user_id');

    // ลบข้อมูลตาม schema ของคุณ (ตัวอย่าง: ลบจาก redeem_logs -> otc -> users)
    await pool.query('BEGIN');
    const u = await pool.query('SELECT id FROM users WHERE facebook_id=$1', [userId]);
    if (u.rowCount) {
      const uid = u.rows[0].id;
      await pool.query('DELETE FROM redeem_logs WHERE uid=$1', [uid]);
      await pool.query('DELETE FROM otc WHERE used_by=$1', [uid]);
      await pool.query('DELETE FROM users WHERE id=$1', [uid]);
    }
    await pool.query('COMMIT');

    // สร้างโค้ดยืนยัน & url ให้ผู้ใช้ตรวจสอบสถานะ
    const confirmation = crypto.randomBytes(8).toString('hex');
    const base = process.env.PUBLIC_BASE_URL || 'https://backend-reward-2o59.onrender.com';
    const statusUrl = `${base}/facebook/deletion-status?code=${confirmation}`;

    // ✅ รูปแบบการตอบกลับที่ Facebook ต้องการ
    return res.json({
      url: statusUrl,
      confirmation_code: confirmation
    });
  } catch (err) {
    try { await pool.query('ROLLBACK'); } catch {}
    return res.status(500).send('internal error');
  }
});

// ---------- 2) Data Deletion Instructions (ผู้ใช้เปิดอ่านเอง) ----------
router.get('/facebook/deletion-instructions', (_req, res) => {
  const contact = process.env.PRIVACY_CONTACT_EMAIL || 'support@example.com';
  res.type('text/plain').send(
`การลบข้อมูลผู้ใช้ (Facebook Login)

- คุณสามารถยื่นคำขอลบข้อมูลผ่าน Facebook ได้ที่เมนู “ลบบัญชีจากแอพนี้”
- เมื่อเราได้รับคำขอจาก Facebook ระบบจะลบข้อมูลบัญชีที่เชื่อมกับคุณ และออกโค้ดยืนยัน
- คุณสามารถตรวจสอบสถานะได้ที่ลิงก์ที่ส่งคืนจากคำขอ (deletion-status)

ติดต่อผู้ดูแลระบบ: ${contact}`
  );
});

// ---------- 3) Status Page (optional) ----------
router.get('/facebook/deletion-status', (req, res) => {
  // ในตัวอย่างนี้ไม่ผูกสถานะจริง แสดงยืนยันแบบคงที่
  res.type('text/plain').send('คำขอลบข้อมูลของคุณถูกดำเนินการแล้ว หากมีข้อสงสัยโปรดติดต่อผู้ดูแลระบบ');
});

export default router;

// ---------- helper ----------
function b64urlToBuf(s: string) {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}
