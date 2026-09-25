import Database from "better-sqlite3";

const db = new Database("notes.db");

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
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    verified INTEGER DEFAULT 0,
    verificationToken TEXT,
    resetToken TEXT,
    resetTokenExpiry INTEGER
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS business_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER UNIQUE NOT NULL,
    businessName TEXT,
    trn TEXT,
    address TEXT,
    email TEXT,
    phone TEXT,
    FOREIGN KEY (userId) REFERENCES users(id)
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    name TEXT NOT NULL,
    email TEXT,
    trn TEXT,
    address TEXT,
    FOREIGN KEY (userId) REFERENCES users(id)
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER NOT NULL,
    clientId INTEGER,
    invoiceNumber TEXT NOT NULL,
    issueDate TEXT DEFAULT CURRENT_TIMESTAMP,
    dueDate TEXT,
    status TEXT DEFAULT 'unpaid',
    currency TEXT DEFAULT 'AED',
    sellerName TEXT NOT NULL,
    sellerTRN TEXT NOT NULL,
    clientName TEXT NOT NULL,
    clientEmail TEXT,
    clientTRN TEXT,
    FOREIGN KEY (userId) REFERENCES users(id),
    FOREIGN KEY (clientId) REFERENCES clients(id)
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS invoice_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    invoiceId INTEGER NOT NULL,
    description TEXT NOT NULL,
    quantity REAL NOT NULL,
    unitPrice REAL NOT NULL,
    vatRate REAL DEFAULT 5,
    FOREIGN KEY (invoiceId) REFERENCES invoices(id)
  )
`);

export default db;