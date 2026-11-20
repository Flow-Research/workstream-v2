PRAGMA foreign_keys=ON;
PRAGMA secure_delete=ON;
CREATE TABLE IF NOT EXISTS grants (
  subject TEXT NOT NULL, task TEXT NOT NULL, digest TEXT NOT NULL,
  operation TEXT NOT NULL CHECK(operation IN ('read','upload')),
  PRIMARY KEY(subject,task,digest,operation)
);
CREATE TABLE IF NOT EXISTS objects (
  task TEXT NOT NULL, digest TEXT NOT NULL, body BLOB NOT NULL,
  PRIMARY KEY(task,digest)
);
CREATE TABLE IF NOT EXISTS tickets (
  subject TEXT NOT NULL, task TEXT NOT NULL, digest TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE, expires INTEGER NOT NULL,
  PRIMARY KEY(subject,task,digest),
  FOREIGN KEY(task,digest) REFERENCES objects(task,digest) ON DELETE CASCADE
);
