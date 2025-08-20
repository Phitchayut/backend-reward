import passport from 'passport';
import { Strategy as FacebookStrategy, Profile } from 'passport-facebook';
import { pool } from './db';

const FB_APP_ID = process.env.FB_APP_ID!;
const FB_APP_SECRET = process.env.FB_APP_SECRET!;
const FB_CALLBACK_URL = process.env.FB_CALLBACK_URL!;

passport.serializeUser((user: any, done) => done(null, user.id));

passport.deserializeUser(async (id: number, done) => {
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE id=$1', [id]);
    done(null, rows[0] || null);
  } catch (e) {
    done(e);
  }
});

passport.use(new FacebookStrategy(
  {
    clientID: FB_APP_ID,
    clientSecret: FB_APP_SECRET,
    callbackURL: FB_CALLBACK_URL,
    profileFields: ['id', 'displayName', 'photos']
  },
  async (_accessToken: string, _refreshToken: string, profile: Profile, done) => {
    try {
      const fbId = profile.id;
      const disp = profile.displayName;
      const photo = profile.photos?.[0]?.value ?? null;

      const existing = await pool.query('SELECT * FROM users WHERE facebook_id=$1', [fbId]);
      if (existing.rows.length) return done(null, existing.rows[0]);

      const inserted = await pool.query(
        'INSERT INTO users (facebook_id, display_name, photo, stamp_count, updated_at) VALUES ($1,$2,$3,0,0) RETURNING *',
        [fbId, disp, photo]
      );
      return done(null, inserted.rows[0]);
    } catch (e) {
      return done(e as any);
    }
  }
));

export default passport;
