import express from 'express';
import { pool } from './db';

const router = express.Router();

// เบื้องต้น (dev): รับ user_id ตรง ๆ
router.post('/facebook/deletion', async (req, res) => {
  const { user_id } = req.body || {};
  if (!user_id) return res.status(400).json({ error: 'Missing user_id' });

  // ลบผู้ใช้และประวัติ (อิงจาก facebook_id)
  await pool.query('DELETE FROM redeem_logs WHERE uid IN (SELECT id FROM users WHERE facebook_id=$1)', [user_id]);
  await pool.query('DELETE FROM users WHERE facebook_id=$1', [user_id]);

  const code = `DEL-${Date.now()}-${Math.random().toString(36).slice(2,8).toUpperCase()}`;
  return res.json({
    url: `https://yourdomain.com/deletion-status/${code}`,
    confirmation_code: code
  });
});

export default router;
