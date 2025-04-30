const express = require("express");
const multer = require("multer");
const cors = require("cors");
const bcrypt = require("bcrypt");
const db = require("./db");
const app = express();
const port = 8000;

// Middleware to parse JSON
const upload = multer();

// CORS setup
app.use(
  cors({
    origin: "http://localhost:5173", // Or '*' for all origins (development)
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

    if (!user) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    try {
      const match = await bcrypt.compare(password, user.password);

      if (match) {
        return res.status(200).json({ message: "Login successful!" });
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
  const { name, email, password } = req.body;
  const saltRounds = 10;

  if (!name || !email || !password) {
    return res.status(400).json({ message: "All fields are required." });
  }

  if (!validateEmail(email)) {
    return res.status(400).send("Invalid email address.");
  }

  if (!validatePassword(password)) {
    return res.status(400).send("Password must be at least 8 characters long.");
  }

  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const sql = "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";
    const params = [name, email, hashedPassword];

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

app.listen(port, () => {
  console.log(`Server is running on this ${port}`);
});
