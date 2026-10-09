const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is not configured");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS projects (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      owner TEXT NOT NULL,
      progress INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL DEFAULT 'In Progress'
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS tasks (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      completed BOOLEAN NOT NULL DEFAULT FALSE
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS session (
      sid VARCHAR(255) PRIMARY KEY,
      sess JSON NOT NULL,
      expire TIMESTAMPTZ NOT NULL
    )
  `);
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.set("trust proxy", 1);

app.use(
  session({
    store: new pgSession({
      pool,
      tableName: "session",
      createTableIfMissing: true
    }),
    secret: process.env.SESSION_SECRET || "change-this-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 24 * 60 * 60 * 1000
    }
  })
);

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.redirect("/");
  }
  next();
}

function startUserSession(req, userId) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);

      req.session.userId = userId;
      req.session.save((saveErr) => {
        if (saveErr) return reject(saveErr);
        resolve();
      });
    });
  });
}

app.get("/", (req, res) => {
  if (req.session.userId) return res.redirect("/dashboard");
  res.sendFile(path.join(__dirname, "workout.html"));
});

app.get("/dashboard", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "dashboard.html"));
});

app.get("/welcome", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "welcome.html"));
});

app.post("/register", async (req, res) => {
  const name = typeof req.body.name === "string" ? req.body.name.trim() : "";
  const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body.password === "string" ? req.body.password : "";

  if (!name || !email || !password) {
    return res.status(400).json({ message: "All fields are required." });
  }

  if (password.length < 8) {
    return res.status(400).json({ message: "Password must be at least 8 characters." });
  }

  try {
    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id",
      [name, email, hash]
    );

    await startUserSession(req, result.rows[0].id);

    return res.status(201).json({ message: "Registration successful." });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ message: "An account with that email already exists." });
    }
    console.error(error);
    return res.status(500).json({ message: "Registration failed." });
  }
});

app.post("/login", async (req, res) => {
  const email = typeof req.body.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body.password === "string" ? req.body.password : "";

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required." });
  }

  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

    if (result.rows.length === 0) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    await startUserSession(req, user.id);
    return res.json({ message: "Login successful." });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Login failed." });
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).send("Logout failed.");

    res.clearCookie("connect.sid");
    res.redirect("/");
  });
});

app.get("/api/me", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT name FROM users WHERE id = $1",
      [req.session.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    res.json({ name: result.rows[0].name });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Could not load your profile." });
  }
});

app.get("/api/projects", requireAuth, async (req, res) => {
  const result = await pool.query(
    "SELECT id, name, owner, progress, status FROM projects WHERE user_id = $1 ORDER BY id DESC",
    [req.session.userId]
  );

  res.json(result.rows);
});

app.post("/api/projects", requireAuth, async (req, res) => {
  const name = typeof req.body.name === "string" ? req.body.name.trim() : "";

  if (!name) {
    return res.status(400).json({ message: "Enter a project name." });
  }

  const result = await pool.query(
    "INSERT INTO projects (user_id, name, owner) VALUES ($1, $2, $3) RETURNING id, name, owner, progress, status",
    [req.session.userId, name, "You"]
  );

  res.status(201).json(result.rows[0]);
});

app.patch("/api/projects/:id", requireAuth, async (req, res) => {
  const projectId = Number(req.params.id);
  const progress = Number(req.body.progress);
  const status = req.body.status;

  if (!Number.isInteger(projectId)) {
    return res.status(400).json({ message: "Invalid project id." });
  }

  if (!Number.isInteger(progress) || progress < 0 || progress > 100) {
    return res.status(400).json({ message: "Progress must be between 0 and 100." });
  }

  if (!["In Progress", "Review", "Done"].includes(status)) {
    return res.status(400).json({ message: "Invalid status." });
  }

  const result = await pool.query(
    "UPDATE projects SET progress = $1, status = $2 WHERE id = $3 AND user_id = $4 RETURNING id",
    [progress, status, projectId, req.session.userId]
  );

  if (result.rows.length === 0) {
    return res.status(404).json({ message: "Project not found." });
  }

  res.json({ message: "Project updated." });
});

app.delete("/api/projects/:id", requireAuth, async (req, res) => {
  const result = await pool.query(
    "DELETE FROM projects WHERE id = $1 AND user_id = $2 RETURNING id",
    [req.params.id, req.session.userId]
  );

  if (result.rows.length === 0) {
    return res.status(404).json({ message: "Project not found." });
  }

  res.sendStatus(204);
});

app.get("/api/tasks", requireAuth, async (req, res) => {
  const result = await pool.query(`
    SELECT
      tasks.id,
      tasks.title,
      tasks.completed,
      tasks.project_id,
      projects.name AS project_name
    FROM tasks
    JOIN projects ON projects.id = tasks.project_id
    WHERE tasks.user_id = $1
    ORDER BY tasks.id DESC
  `, [req.session.userId]);

  res.json(result.rows);
});

app.post("/api/tasks", requireAuth, async (req, res) => {
  const title = typeof req.body.title === "string" ? req.body.title.trim() : "";
  const projectId = Number(req.body.projectId);

  if (!title || title.length > 200 || !Number.isInteger(projectId)) {
    return res.status(400).json({ message: "Enter a task name and choose a project." });
  }

  const projectCheck = await pool.query(
    "SELECT id FROM projects WHERE id = $1 AND user_id = $2",
    [projectId, req.session.userId]
  );

  if (projectCheck.rows.length === 0) {
    return res.status(400).json({ message: "Choose one of your projects." });
  }

  const result = await pool.query(
    "INSERT INTO tasks (user_id, project_id, title) VALUES ($1, $2, $3) RETURNING id",
    [req.session.userId, projectId, title]
  );

  res.status(201).json({ id: result.rows[0].id });
});

app.patch("/api/tasks/:id", requireAuth, async (req, res) => {
  if (typeof req.body.completed !== "boolean") {
    return res.status(400).json({ message: "Invalid completion value." });
  }

  const result = await pool.query(
    "UPDATE tasks SET completed = $1 WHERE id = $2 AND user_id = $3 RETURNING id",
    [req.body.completed, req.params.id, req.session.userId]
  );

  if (result.rows.length === 0) {
    return res.status(404).json({ message: "Task not found." });
  }

  res.sendStatus(204);
});

app.delete("/api/tasks/:id", requireAuth, async (req, res) => {
  const result = await pool.query(
    "DELETE FROM tasks WHERE id = $1 AND user_id = $2 RETURNING id",
    [req.params.id, req.session.userId]
  );

  if (result.rows.length === 0) {
    return res.status(404).json({ message: "Task not found." });
  }

  res.sendStatus(204);
});

app.get("/ai-motion.css", (req, res) => {
  res.sendFile(path.join(__dirname, "ai-motion.css"));
});

initDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Database init error:", error);
    process.exit(1);
  });

