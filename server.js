const express = require("express");
const multer = require("multer");
const cors = require("cors");
const bcrypt = require("bcrypt");
const db = require("./db");
const app = express();
const port = 8000;

// Middleware to parse JSON
app.use(express.json());
const upload = multer();

// CORS setup
app.use(
  cors({
    origin: "*", // Or '*' for all origins (development)
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"], // Allowed HTTP methods
    allowedHeaders: ["Content-Type", "Authorization"], // Allowed headers
  })
);

const validateEmail = (email) => {
  var re = /\S+@\S+\.\S+/;
  return re.test(email);
};

const validatePassword = (password) => {
  const passwordRegex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\|]).{8,}$/;
  return passwordRegex.test(password);
};

app.get("/", (req, res) => {
  res.send("hello Ram!");
});

app.post("/login", upload.none(), (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "All fields are required." });
  }

  const sql = "SELECT * FROM users WHERE email = ?";
  const params = [email];

  db.get(sql, params, async (err, user) => {
    if (err) {
      console.error("Error querying user:", err.message);
      return res.status(500).json({ message: "Internal server error." });
    }

    if (!user || user.active !== 1) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    // Optional: Check email verification
    // if (user.email_verified !== 1) {
    //   return res.status(403).json({ message: "Please verify your email before logging in." });
    // }

    try {
      const match = await bcrypt.compare(password, user.password);

      if (match) {
        // Update last_login
        const updateSql =
          "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?";
        db.run(updateSql, [user.id], (updateErr) => {
          if (updateErr) {
            console.error("Failed to update last login:", updateErr.message);
          }
        });

        return res.status(200).json({
          message: "Login successful!",
          user: {
            id: user.id,
            name: user.name,
            username: user.username,
            email: user.email,
            role: user.role,
          },
        });
      } else {
        return res.status(401).json({ message: "Invalid email or password." });
      }
    } catch (error) {
      console.error("Error comparing passwords:", error.message);
      return res.status(500).json({ message: "Internal server error." });
    }
  });
});

app.post("/signup", upload.none(), async (req, res) => {
  const { name, username, email, password, phone } = req.body;
  const saltRounds = 10;

  if (!name || !email || !password || !phone) {
    return res.status(400).json({ message: "All fields are required." });
  }

  if (!validateEmail(email)) {
    return res.status(400).send("Invalid email address.");
  }

  if (!validatePassword(password)) {
    return res.status(400).send("Password must be at least 8 characters long.");
  }

  if (!/^\d{10,15}$/.test(phone)) {
    return res
      .status(400)
      .json({ message: "A valid phone number is required." });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);

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
      if (err) {
        console.error("Error inserting user:", err.message);
        return res.status(500).json({ message: "Failed to create user." });
      }
      res.status(201).json({ message: "User successfully registered!!" });
    });
  } catch (error) {
    console.error("Hashing error:", error.message);
    res.status(500).json({ message: "Internal server error." });
  }
});

app.get("/dashboard", (req, res) => {
  const sql = "SELECT * FROM users";
  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error("Error fetching user data:", err.message);
      return res.status(500).json({ message: "Failed to fetch user data." });
    }
    res.status(200).json(rows);
  });
});

// GET user by ID
app.get("/api/users/:id", (req, res) => {
  console.log("req.params;", req.params);
  const { id } = req.params;
  db.get("SELECT * FROM users WHERE id = ?", [id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(row);
  });
});

// PUT update user
app.put("/users/:id", (req, res) => {
  console.log("req.params;", req.params);
  const { id } = req.params;
  const { name, email, phone, role, active } = req.body;

  const sql = `
    UPDATE users
    SET name = ?, email = ?, phone = ?, role = ?, active = ?
    WHERE id = ?
  `;
  const params = [name, email, phone, role, active, id];

  db.run(sql, params, function (err) {
    if (err) return res.status(500).json({ message: "Update failed." });
    res.json({ message: "User updated successfully." });
  });
});

app.listen(port, () => {
  console.log(`Server is running on this ${port}`);
});
