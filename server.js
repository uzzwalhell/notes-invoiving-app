import express from "express";
import db from "./db.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import PDFDocument from "pdfkit";
import "dotenv/config";

const JWT_SECRET = process.env.JWT_SECRET;
const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static("public"));

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: "No token provided" });
  }
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

app.get("/", (req, res) => {
  res.send("Notes & Invoicing API is running!");
});

app.post("/signup", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)").run(username, hashedPassword);
    res.json({ message: "User created!", userId: result.lastInsertRowid });
  } catch (err) {
    res.status(400).json({ error: "Username already taken" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!user) {
    return res.status(401).json({ error: "Invalid username or password" });
  }
  const passwordMatches = await bcrypt.compare(password, user.password);
  if (!passwordMatches) {
    return res.status(401).json({ error: "Invalid username or password" });
  }
  const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: "1h" });
  res.json({ message: "Login successful!", token });
});

// ---------- INVOICES ----------

// CREATE an invoice with line items
app.post("/invoices", requireAuth, (req, res) => {
  const { invoiceNumber, clientName, clientEmail, dueDate, items } = req.body;

  if (!invoiceNumber || !clientName || !items || items.length === 0) {
    return res.status(400).json({ error: "invoiceNumber, clientName, and at least one item are required" });
  }

  const insertInvoice = db.prepare(`
    INSERT INTO invoices (userId, invoiceNumber, clientName, clientEmail, dueDate)
    VALUES (?, ?, ?, ?, ?)
  `);
  const invoiceResult = insertInvoice.run(req.user.userId, invoiceNumber, clientName, clientEmail, dueDate);
  const invoiceId = invoiceResult.lastInsertRowid;

  const insertItem = db.prepare(`
    INSERT INTO invoice_items (invoiceId, description, quantity, unitPrice)
    VALUES (?, ?, ?, ?)
  `);
  items.forEach((item) => {
    insertItem.run(invoiceId, item.description, item.quantity, item.unitPrice);
  });

  res.json({ message: "Invoice created!", invoiceId });
});

// LIST all invoices for the logged-in user
app.get("/invoices", requireAuth, (req, res) => {
  const invoices = db.prepare("SELECT * FROM invoices WHERE userId = ?").all(req.user.userId);
  res.json(invoices);
});

// GET one invoice with its items and calculated total
app.get("/invoices/:id", requireAuth, (req, res) => {
  const invoice = db.prepare("SELECT * FROM invoices WHERE id = ? AND userId = ?").get(req.params.id, req.user.userId);

  if (!invoice) {
    return res.status(404).json({ error: "Invoice not found" });
  }

  const items = db.prepare("SELECT * FROM invoice_items WHERE invoiceId = ?").all(invoice.id);
  const total = items.reduce((sum, item) => sum + item.quantity * item.unitPrice, 0);

  res.json({ ...invoice, items, total });
});

// DELETE an invoice (and its items)
app.delete("/invoices/:id", requireAuth, (req, res) => {
  const invoice = db.prepare("SELECT * FROM invoices WHERE id = ? AND userId = ?").get(req.params.id, req.user.userId);

  if (!invoice) {
    return res.status(404).json({ error: "Invoice not found" });
  }

  db.prepare("DELETE FROM invoice_items WHERE invoiceId = ?").run(invoice.id);
  db.prepare("DELETE FROM invoices WHERE id = ?").run(invoice.id);

  res.json({ message: "Invoice deleted" });
});

// GENERATE a PDF for an invoice
app.get("/invoices/:id/pdf", requireAuth, (req, res) => {
  const invoice = db.prepare("SELECT * FROM invoices WHERE id = ? AND userId = ?").get(req.params.id, req.user.userId);

  if (!invoice) {
    return res.status(404).json({ error: "Invoice not found" });
  }

  const items = db.prepare("SELECT * FROM invoice_items WHERE invoiceId = ?").all(invoice.id);
  const total = items.reduce((sum, item) => sum + item.quantity * item.unitPrice, 0);

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `attachment; filename=invoice-${invoice.invoiceNumber}.pdf`);

  const doc = new PDFDocument();
  doc.pipe(res);

  doc.fontSize(20).text(`Invoice ${invoice.invoiceNumber}`, { align: "left" });
  doc.moveDown();
  doc.fontSize(12).text(`Client: ${invoice.clientName}`);
  if (invoice.clientEmail) doc.text(`Email: ${invoice.clientEmail}`);
  doc.text(`Issue Date: ${invoice.issueDate}`);
  if (invoice.dueDate) doc.text(`Due Date: ${invoice.dueDate}`);
  doc.text(`Status: ${invoice.status}`);
  doc.moveDown();

  doc.fontSize(14).text("Items:", { underline: true });
  items.forEach((item) => {
    const lineTotal = (item.quantity * item.unitPrice).toFixed(2);
    doc.fontSize(12).text(`${item.description} — Qty: ${item.quantity} x $${item.unitPrice} = $${lineTotal}`);
  });

  doc.moveDown();
  doc.fontSize(14).text(`Total: $${total.toFixed(2)}`, { align: "right" });

  doc.end();
});

// ---------- NOTES (unchanged from before) ----------

app.get("/notes", requireAuth, (req, res) => {
  const notes = db.prepare("SELECT * FROM notes").all();
  res.json(notes);
});

app.post("/notes", requireAuth, (req, res) => {
  const text = req.body.text;
  if (!text) {
    return res.status(400).json({ error: "Note text is required" });
  }
  const result = db.prepare("INSERT INTO notes (text) VALUES (?)").run(text);
  res.json({ message: "Note saved!", id: result.lastInsertRowid });
});

app.put("/notes/:id", requireAuth, (req, res) => {
  const id = req.params.id;
  const newText = req.body.text;
  if (!newText) {
    return res.status(400).json({ error: "Note text is required" });
  }
  const result = db.prepare("UPDATE notes SET text = ? WHERE id = ?").run(newText, id);
  if (result.changes === 0) {
    return res.status(404).json({ error: "Note not found" });
  }
  res.json({ message: `Note ${id} updated` });
});

app.delete("/notes/:id", requireAuth, (req, res) => {
  const id = req.params.id;
  db.prepare("DELETE FROM notes WHERE id = ?").run(id);
  res.json({ message: `Note ${id} deleted` });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});