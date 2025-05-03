const express = require("express");
const multer = require("multer");
const cors = require("cors");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const bodyParser = require("body-parser");
const db = require("./db");

const app = express();
const port = 8000;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
const upload = multer();

// CORS setup
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// Email & Password Validators
const validateEmail = (email) => /\S+@\S+\.\S+/.test(email);
const validatePassword = (password) =>
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\|]).{8,}$/.test(
    password
  );

// In-memory token store
const resetTokens = {};

// Routes
app.get("/", (req, res) => {
  res.send("hello Ram!");
});

app.post("/login", upload.none(), (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: "All fields are required." });

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err) return res.status(500).json({ message: "Internal server error." });
    if (!user || user.active !== 1)
      return res.status(401).json({ message: "Invalid email or password." });

    try {
      const match = await bcrypt.compare(password, user.password);
      if (!match)
        return res.status(401).json({ message: "Invalid email or password." });

      db.run(
        "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
        [user.id],
        (updateErr) => {
          if (updateErr)
            console.error("Failed to update last login:", updateErr.message);
        }
      );

      res.status(200).json({
        message: "Login successful!",
        user: {
          id: user.id,
          name: user.name,
          username: user.username,
          email: user.email,
          role: user.role,
        },
      });
    } catch (error) {
      res.status(500).json({ message: "Internal server error." });
    }
  });
});

app.post("/signup", upload.none(), async (req, res) => {
  const { name, username, email, password, phone } = req.body;
  if (!name || !email || !password || !phone)
    return res.status(400).json({ message: "All fields are required." });

  if (!validateEmail(email))
    return res.status(400).send("Invalid email address.");
  if (!validatePassword(password))
    return res.status(400).send("Password must be at least 8 characters long.");
  if (!/^\d{10,15}$/.test(phone))
    return res
      .status(400)
      .json({ message: "A valid phone number is required." });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = `
      INSERT INTO users (name, username, email, password, phone, role, active, email_verified)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const params = [
      name,
      username || null,
      email,
      hashedPassword,
      phone,
      "user",
      1,
      0,
    ];

    db.run(sql, params, function (err) {
      if (err)
        return res.status(500).json({ message: "Failed to create user." });
      res.status(201).json({ message: "User successfully registered!!" });
    });
  } catch (error) {
    res.status(500).json({ message: "Internal server error." });
  }
});

// Forgot Password
app.post("/forgot-password", (req, res) => {
  const { email } = req.query;
  console.log("email", email);

  if (!email || !validateEmail(email)) {
    return res.status(400).json({ message: "Valid email is required." });
  }

  db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
    if (err) return res.status(500).json({ message: "Internal server error." });
    if (!user) return res.status(404).json({ message: "User not found." });

    const token = crypto.randomBytes(20).toString("hex");
    resetTokens[token] = { email, expires: Date.now() + 3600000 }; // 1 hour

    const resetLink = `https://backend-xz4u.onrender.com/reset-password/${token}`;
    console.log("🔗 Reset link:", resetLink);

    // In real app: send email with link
    res.status(200).json({
      message: "Password reset link has been generated.",
      resetLink,
    });
  });
});

// Reset Password
app.post("/reset-password/:token", upload.none(), async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  if (!password || !validatePassword(password)) {
    return res.status(400).json({ message: "Invalid or weak password." });
  }

  const tokenData = resetTokens[token];
  if (!tokenData || Date.now() > tokenData.expires) {
    return res
      .status(400)
      .json({ message: "Reset link has expired or is invalid." });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  db.run(
    "UPDATE users SET password = ? WHERE email = ?",
    [hashedPassword, tokenData.email],
    function (err) {
      if (err)
        return res.status(500).json({ message: "Failed to reset password." });

      delete resetTokens[token];
      res
        .status(200)
        .json({ message: "Password has been reset successfully!" });
    }
  );
});

// Dashboard routes
app.get("/dashboard", (req, res) => {
  res.send("Welcome to Dashboard Page we are working on it.");
});

app.get("/user-dashboard", (req, res) => {
  db.all("SELECT * FROM users", [], (err, rows) => {
    if (err)
      return res.status(500).json({ message: "Failed to fetch user data." });
    res.status(200).json(rows);
  });
});

app.get("/api/users/:id", (req, res) => {
  const { id } = req.params;
  db.get("SELECT * FROM users WHERE id = ?", [id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(row);
  });
});

app.put("/users/:id", (req, res) => {
  const { id } = req.params;
  const { name, email, phone, role, active } = req.body;
  db.run(
    `UPDATE users SET name = ?, email = ?, phone = ?, role = ?, active = ? WHERE id = ?`,
    [name, email, phone, role, active, id],
    function (err) {
      if (err) return res.status(500).json({ message: "Update failed." });
      res.json({ message: "User updated successfully." });
    }
  );
});

app.listen(port, () => {
  console.log(`✅ Server is running at http://localhost:${port}`);
});
