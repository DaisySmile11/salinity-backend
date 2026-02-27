import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import pkg from "pg";

dotenv.config();
const { Pool } = pkg;

const app = express();

/**
 * CORS:
 * - Khi dev local: cho phép tất cả (origin: true)
 * - Khi deploy: bạn có thể set ALLOWED_ORIGINS="https://salinity.site,https://www.salinity.site"
 */
const allowed = (process.env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: allowed.length ? allowed : true,
  credentials: true
}));

app.use(express.json());

if (!process.env.DATABASE_URL) {
  console.warn("⚠️ DATABASE_URL is missing. Set it in .env (local) or Render env vars (deploy).");
}

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const JWT_SECRET = process.env.JWT_SECRET || "change_me_in_env";

/** ----- Auth helpers ----- */
function signToken(admin) {
  return jwt.sign(
    { id: admin.id, email: admin.email, role: admin.role },
    JWT_SECRET,
    { expiresIn: "12h" }
  );
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function requireSuper(req, res, next) {
  if (req.user?.role !== "superadmin") return res.status(403).json({ error: "Forbidden" });
  next();
}

/** ----- Ensure default thresholds exists ----- */
async function ensureThresholdsRow() {
  const { rows } = await pool.query("SELECT * FROM thresholds WHERE id=1");
  if (rows.length) return;

  await pool.query(
    `INSERT INTO thresholds
      (id, sal_low, sal_high, ph_low, ph_high, temp_low, temp_high, bat_low, offline_minutes)
     VALUES (1, 8, 12, 6.5, 8.5, 25, 32, 20, 10)`
  );
}

/** ----- Health ----- */
app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, db: "down" });
  }
});

/** ----- Thresholds (public GET) ----- */
app.get("/thresholds", async (req, res) => {
  try {
    await ensureThresholdsRow();
    const { rows } = await pool.query("SELECT * FROM thresholds WHERE id=1");
    res.json(rows[0] || null);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to load thresholds" });
  }
});

/** ----- Thresholds (admin PUT) ----- */
app.put("/thresholds", auth, async (req, res) => {
  try {
    await ensureThresholdsRow();

    const t = req.body || {};
    // Basic validation (numbers)
    const mustNum = (v, name) => {
      const n = Number(v);
      if (!Number.isFinite(n)) throw new Error(`Invalid ${name}`);
      return n;
    };
    const mustInt = (v, name) => {
      const n = parseInt(v, 10);
      if (!Number.isFinite(n)) throw new Error(`Invalid ${name}`);
      return n;
    };

    const payload = {
      sal_low: mustNum(t.sal_low, "sal_low"),
      sal_high: mustNum(t.sal_high, "sal_high"),
      ph_low: mustNum(t.ph_low, "ph_low"),
      ph_high: mustNum(t.ph_high, "ph_high"),
      temp_low: mustNum(t.temp_low, "temp_low"),
      temp_high: mustNum(t.temp_high, "temp_high"),
      bat_low: mustNum(t.bat_low, "bat_low"),
      offline_minutes: mustInt(t.offline_minutes, "offline_minutes"),
    };

    const q = `
      UPDATE thresholds SET
        sal_low=$1, sal_high=$2,
        ph_low=$3, ph_high=$4,
        temp_low=$5, temp_high=$6,
        bat_low=$7, offline_minutes=$8,
        updated_at=NOW(), updated_by=$9
      WHERE id=1
      RETURNING *;
    `;
    const values = [
      payload.sal_low, payload.sal_high,
      payload.ph_low, payload.ph_high,
      payload.temp_low, payload.temp_high,
      payload.bat_low, payload.offline_minutes,
      req.user.id
    ];
    const { rows } = await pool.query(q, values);
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(/Invalid /.test(String(e?.message||"")) ? 400 : 500).json({ error: e?.message || "Failed to update thresholds" });
  }
});

/** ----- Login ----- */
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "Missing email/password" });

    const { rows } = await pool.query(
      "SELECT id,email,password_hash,role,active FROM admins WHERE email=$1 AND active=true",
      [email]
    );
    const admin = rows[0];
    if (!admin) return res.status(401).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, admin.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    res.json({
      token: signToken(admin),
      admin: { id: admin.id, email: admin.email, role: admin.role }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Login failed" });
  }
});

/** ----- Admin management (optional; superadmin only) ----- */
app.get("/admins", auth, requireSuper, async (req, res) => {
  const { rows } = await pool.query(
    "SELECT id,email,role,active,created_at FROM admins ORDER BY created_at DESC"
  );
  res.json(rows);
});

app.post("/admins", auth, requireSuper, async (req, res) => {
  const { email, password, role } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Missing email/password" });

  const hash = await bcrypt.hash(password, 10);
  const { rows } = await pool.query(
    "INSERT INTO admins(email,password_hash,role,active) VALUES($1,$2,$3,true) RETURNING id,email,role,active,created_at",
    [email, hash, role || "admin"]
  );
  res.json(rows[0]);
});

app.delete("/admins/:id", auth, requireSuper, async (req, res) => {
  await pool.query("UPDATE admins SET active=false WHERE id=$1", [req.params.id]);
  res.json({ ok: true });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
