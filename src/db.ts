import { Pool } from 'pg';

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Render มักต้องใช้ SSL
  ssl: { rejectUnauthorized: false }
});

export const nowSec = () => Math.floor(Date.now() / 1000);
