import Database from "better-sqlite3";

const db = new Database("notes.db"); // creates the file if it doesn't exist

db.exec(`
  CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    text TEXT NOT NULL,
    createdAt TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  )
`);
db.exec(`
  CREATE TABLE IF NOT EXISTS invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    invoiceNumber TEXT NOT NULL,
    clientName TEXT NOT NULL,
    clientEmail TEXT,
    issueDate TEXT DEFAULT CURRENT_TIMESTAMP,
    dueDate TEXT,
    status TEXT DEFAULT 'unpaid',
    FOREIGN KEY (userId) REFERENCES users(id)
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS invoice_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    invoiceId INTEGER NOT NULL,
    description TEXT NOT NULL,
    quantity REAL NOT NULL,
    unitPrice REAL NOT NULL,
    FOREIGN KEY (invoiceId) REFERENCES invoices(id)
  )
`);
export default db;