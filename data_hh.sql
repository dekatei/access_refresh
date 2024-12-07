CREATE TABLE refresh_tokens (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       user_id TEXT NOT NULL DEFAULT "",
       token_hash TEXT NOT NULL DEFAULT "",
       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
   );