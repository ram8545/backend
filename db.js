const sqlite3 = require("sqlite3").verbose();

const db = new sqlite3.Database("./mydb.db", (err) => {
  if (err) {
    console.error("Database connection error:", err.message);
  } else {
    console.log("Connected to the database.");

    db.run(
      `
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        username TEXT UNIQUE,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        active INTEGER DEFAULT 1,
        email_verified INTEGER DEFAULT 0,
        reset_token TEXT,
        reset_token_expiry TEXT,
        createdate TEXT DEFAULT CURRENT_TIMESTAMP,
        updatedate TEXT DEFAULT CURRENT_TIMESTAMP,
        last_login TEXT,
        phone TEXT,
        avatar_url TEXT,
        bio TEXT
      )
      `,
      (err) => {
        if (err) {
          console.error("Error creating users table:", err.message);
        } else {
          console.log("Users table ready.");
        }
      }
    );
  }
});

module.exports = db;
