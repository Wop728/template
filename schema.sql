-- D1 schema for Cloudflare D1
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  type TEXT NOT NULL,
  title TEXT NOT NULL,
  content TEXT,
  keywords TEXT,
  start_time TEXT,
  end_time TEXT,
  status TEXT DEFAULT 'active',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE matches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  message_id INTEGER NOT NULL,
  matched_message_id INTEGER NOT NULL,
  matched_type TEXT,
  matched_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_messages_keywords ON messages(keywords);
