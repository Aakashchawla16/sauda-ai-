require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 5000;

if (!process.env.JWT_SECRET) {
  console.error("JWT_SECRET is required");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(helmet());
app.use(cors());
app.use(express.json());

function auth(req, res, next) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Authentication required"
    });
  }

  const token = header.substring(7);

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    req.userId = decoded.userId;
    next();
  } catch {
    return res.status(401).json({
      message: "Invalid or expired token"
    });
  }
}

async function setupDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(120) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS leads (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      name VARCHAR(120) NOT NULL,
      phone VARCHAR(40),
      email VARCHAR(255),
      lead_type VARCHAR(80),
      budget VARCHAR(120),
      location VARCHAR(255),
      property_type VARCHAR(100),
      status VARCHAR(50) DEFAULT 'new',
      lead_score INTEGER DEFAULT 0,
      notes TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS properties (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(255) NOT NULL,
      location VARCHAR(255),
      price VARCHAR(120),
      property_type VARCHAR(100),
      bedrooms INTEGER,
      bathrooms INTEGER,
      area VARCHAR(80),
      description TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS followups (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      lead_id INTEGER REFERENCES leads(id) ON DELETE CASCADE,
      due_at TIMESTAMP,
      note TEXT,
      status VARCHAR(50) DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS deals (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      lead_id INTEGER REFERENCES leads(id) ON DELETE SET NULL,
      property_id INTEGER REFERENCES properties(id) ON DELETE SET NULL,
      amount NUMERIC,
      status VARCHAR(50) DEFAULT 'open',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS conversations (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      lead_id INTEGER REFERENCES leads(id) ON DELETE CASCADE,
      channel VARCHAR(40),
      message TEXT,
      direction VARCHAR(20),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      status: "ok",
      service: "SAUDA AI",
      database: "connected"
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      status: "error",
      database: "not connected"
    });
  }
});

app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        message: "Name, email and password are required"
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        message: "Password must be at least 8 characters"
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `
      INSERT INTO users
      (name, email, password_hash)
      VALUES ($1,$2,$3)
      RETURNING id,name,email,created_at
      `,
      [
        name.trim(),
        email.trim().toLowerCase(),
        hash
      ]
    );

    const user = result.rows[0];

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(201).json({
      message: "Account created",
      token,
      user
    });

  } catch (error) {

    if (error.code === "23505") {
      return res.status(409).json({
        message: "Email already registered"
      });
    }

    console.error(error);

    res.status(500).json({
      message: "Server error"
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {

    const { email, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE email=$1",
      [email.trim().toLowerCase()]
    );

    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      message: "Server error"
    });
  }
});

app.get("/api/leads", auth, async (req, res) => {

  const result = await pool.query(
    `
    SELECT *
    FROM leads
    WHERE user_id=$1
    ORDER BY created_at DESC
    `,
    [req.userId]
  );

  res.json({
    leads: result.rows
  });
});

app.post("/api/leads", auth, async (req, res) => {

  const {
    name,
    phone,
    email,
    lead_type,
    budget,
    location,
    property_type,
    status,
    lead_score,
    notes
  } = req.body;

  if (!name) {
    return res.status(400).json({
      message: "Lead name required"
    });
  }

  const result = await pool.query(
    `
    INSERT INTO leads
    (
      user_id,
      name,
      phone,
      email,
      lead_type,
      budget,
      location,
      property_type,
      status,
      lead_score,
      notes
    )
    VALUES
    ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
    RETURNING *
    `,
    [
      req.userId,
      name,
      phone || null,
      email || null,
      lead_type || null,
      budget || null,
      location || null,
      property_type || null,
      status || "new",
      lead_score || 0,
      notes || null
    ]
  );

  res.status(201).json({
    lead: result.rows[0]
  });
});

app.get("/api/properties", auth, async (req, res) => {

  const result = await pool.query(
    `
    SELECT *
    FROM properties
    WHERE user_id=$1
    ORDER BY created_at DESC
    `,
    [req.userId]
  );

  res.json({
    properties: result.rows
  });
});

app.post("/api/properties", auth, async (req, res) => {

  const {
    title,
    location,
    price,
    property_type,
    bedrooms,
    bathrooms,
    area,
    description
  } = req.body;

  if (!title) {
    return res.status(400).json({
      message: "Property title required"
    });
  }

  const result = await pool.query(
    `
    INSERT INTO properties
    (
      user_id,
      title,
      location,
      price,
      property_type,
      bedrooms,
      bathrooms,
      area,
      description
    )
    VALUES
    ($1,$2,$3,$4,$5,$6,$7,$8,$9)
    RETURNING *
    `,
    [
      req.userId,
      title,
      location || null,
      price || null,
      property_type || null,
      bedrooms || null,
      bathrooms || null,
      area || null,
      description || null
    ]
  );

  res.status(201).json({
    property: result.rows[0]
  });
});

app.get("/api/dashboard", auth, async (req, res) => {

  const leads = await pool.query(
    "SELECT COUNT(*) FROM leads WHERE user_id=$1",
    [req.userId]
  );

  const properties = await pool.query(
    "SELECT COUNT(*) FROM properties WHERE user_id=$1",
    [req.userId]
  );

  const followups = await pool.query(
    "SELECT COUNT(*) FROM followups WHERE user_id=$1 AND status='pending'",
    [req.userId]
  );

  const deals = await pool.query(
    "SELECT COUNT(*) FROM deals WHERE user_id=$1",
    [req.userId]
  );

  res.json({
    leads: Number(leads.rows[0].count),
    properties: Number(properties.rows[0].count),
    followups: Number(followups.rows[0].count),
    deals: Number(deals.rows[0].count)
  });
});

app.listen(PORT, () => {
  console.log(`SAUDA AI running on port ${PORT}`);
});

setupDatabase().catch(error => {
  console.error("Database setup failed:", error);
});