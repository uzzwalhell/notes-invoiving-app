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

app.get("/api", (req, res) => {
  res.send("E-Invoicing API is running!");
});

// ---------- AUTH ----------

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
  const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: "8h" });
  res.json({ message: "Login successful!", token, username: user.username });
});

// ---------- BUSINESS PROFILE ----------

app.get("/profile", requireAuth, (req, res) => {
  const profile = db.prepare("SELECT * FROM business_profiles WHERE userId = ?").get(req.user.userId);
  res.json(profile || {});
});

app.put("/profile", requireAuth, (req, res) => {
  const { businessName, trn, address, email, phone } = req.body;
  const existing = db.prepare("SELECT * FROM business_profiles WHERE userId = ?").get(req.user.userId);

  if (existing) {
    db.prepare(`
      UPDATE business_profiles SET businessName = ?, trn = ?, address = ?, email = ?, phone = ?
      WHERE userId = ?
    `).run(businessName, trn, address, email, phone, req.user.userId);
  } else {
    db.prepare(`
      INSERT INTO business_profiles (userId, businessName, trn, address, email, phone)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(req.user.userId, businessName, trn, address, email, phone);
  }

  res.json({ message: "Profile saved!" });
});

// ---------- CLIENTS ----------

app.get("/clients", requireAuth, (req, res) => {
  const clients = db.prepare("SELECT * FROM clients WHERE userId = ?").all(req.user.userId);
  res.json(clients);
});

app.post("/clients", requireAuth, (req, res) => {
  const { name, email, trn, address } = req.body;
  if (!name) {
    return res.status(400).json({ error: "Client name is required" });
  }
  const result = db.prepare(`
    INSERT INTO clients (userId, name, email, trn, address) VALUES (?, ?, ?, ?, ?)
  `).run(req.user.userId, name, email, trn, address);
  res.json({ message: "Client added!", clientId: result.lastInsertRowid });
});

app.put("/clients/:id", requireAuth, (req, res) => {
  const { name, email, trn, address } = req.body;
  const result = db.prepare(`
    UPDATE clients SET name = ?, email = ?, trn = ?, address = ? WHERE id = ? AND userId = ?
  `).run(name, email, trn, address, req.params.id, req.user.userId);
  if (result.changes === 0) {
    return res.status(404).json({ error: "Client not found" });
  }
  res.json({ message: "Client updated!" });
});

app.delete("/clients/:id", requireAuth, (req, res) => {
  db.prepare("DELETE FROM clients WHERE id = ? AND userId = ?").run(req.params.id, req.user.userId);
  res.json({ message: "Client deleted" });
});

// ---------- DASHBOARD ----------

app.get("/dashboard", requireAuth, (req, res) => {
  const invoices = db.prepare("SELECT * FROM invoices WHERE userId = ?").all(req.user.userId);

  let totalInvoiced = 0;
  let totalUnpaid = 0;

  invoices.forEach((invoice) => {
    const items = db.prepare("SELECT * FROM invoice_items WHERE invoiceId = ?").all(invoice.id);
    const total = items.reduce((sum, item) => sum + item.quantity * item.unitPrice * (1 + item.vatRate / 100), 0);
    totalInvoiced += total;
    if (invoice.status === "unpaid") totalUnpaid += total;
  });

  const recentInvoices = invoices.slice(-5).reverse();

  res.json({
    totalInvoices: invoices.length,
    totalInvoiced: totalInvoiced.toFixed(2),
    totalUnpaid: totalUnpaid.toFixed(2),
    clientCount: db.prepare("SELECT COUNT(*) as count FROM clients WHERE userId = ?").get(req.user.userId).count,
    recentInvoices
  });
});

// ---------- INVOICES ----------

app.post("/invoices", requireAuth, (req, res) => {
  const { invoiceNumber, clientId, clientName, clientEmail, clientTRN, dueDate, currency, items } = req.body;

  const profile = db.prepare("SELECT * FROM business_profiles WHERE userId = ?").get(req.user.userId);
  if (!profile || !profile.businessName || !profile.trn) {
    return res.status(400).json({ error: "Please complete your business profile before creating invoices" });
  }

  if (!invoiceNumber || !clientName || !items || items.length === 0) {
    return res.status(400).json({ error: "invoiceNumber, clientName, and at least one item are required" });
  }

  const insertInvoice = db.prepare(`
    INSERT INTO invoices (userId, clientId, invoiceNumber, sellerName, sellerTRN, clientName, clientEmail, clientTRN, dueDate, currency)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const invoiceResult = insertInvoice.run(
    req.user.userId, clientId || null, invoiceNumber, profile.businessName, profile.trn,
    clientName, clientEmail, clientTRN, dueDate, currency || "AED"
  );
  const invoiceId = invoiceResult.lastInsertRowid;

  const insertItem = db.prepare(`
    INSERT INTO invoice_items (invoiceId, description, quantity, unitPrice, vatRate)
    VALUES (?, ?, ?, ?, ?)
  `);
  items.forEach((item) => {
    insertItem.run(invoiceId, item.description, item.quantity, item.unitPrice, item.vatRate ?? 5);
  });

  res.json({ message: "Invoice created!", invoiceId });
});

app.get("/invoices", requireAuth, (req, res) => {
  const invoices = db.prepare("SELECT * FROM invoices WHERE userId = ? ORDER BY id DESC").all(req.user.userId);
  const withTotals = invoices.map((invoice) => {
    const items = db.prepare("SELECT * FROM invoice_items WHERE invoiceId = ?").all(invoice.id);
    const total = items.reduce((sum, item) => sum + item.quantity * item.unitPrice * (1 + item.vatRate / 100), 0);
    return { ...invoice, total: total.toFixed(2) };
  });
  res.json(withTotals);
});

app.get("/invoices/:id", requireAuth, (req, res) => {
  const invoice = db.prepare("SELECT * FROM invoices WHERE id = ? AND userId = ?").get(req.params.id, req.user.userId);
  if (!invoice) {
    return res.status(404).json({ error: "Invoice not found" });
  }
  const items = db.prepare("SELECT * FROM invoice_items WHERE invoiceId = ?").all(invoice.id);
  const total = items.reduce((sum, item) => sum + item.quantity * item.unitPrice * (1 + item.vatRate / 100), 0);
  res.json({ ...invoice, items, total: total.toFixed(2) });
});

app.put("/invoices/:id/status", requireAuth, (req, res) => {
  const { status } = req.body;
  const result = db.prepare("UPDATE invoices SET status = ? WHERE id = ? AND userId = ?").run(status, req.params.id, req.user.userId);
  if (result.changes === 0) {
    return res.status(404).json({ error: "Invoice not found" });
  }
  res.json({ message: "Status updated" });
});

app.delete("/invoices/:id", requireAuth, (req, res) => {
  const invoice = db.prepare("SELECT * FROM invoices WHERE id = ? AND userId = ?").get(req.params.id, req.user.userId);
  if (!invoice) {
    return res.status(404).json({ error: "Invoice not found" });
  }
  db.prepare("DELETE FROM invoice_items WHERE invoiceId = ?").run(invoice.id);
  db.prepare("DELETE FROM invoices WHERE id = ?").run(invoice.id);
  res.json({ message: "Invoice deleted" });
});

app.get("/invoices/:id/pdf", requireAuth, (req, res) => {
  const invoice = db.prepare("SELECT * FROM invoices WHERE id = ? AND userId = ?").get(req.params.id, req.user.userId);
  if (!invoice) {
    return res.status(404).json({ error: "Invoice not found" });
  }
  const items = db.prepare("SELECT * FROM invoice_items WHERE invoiceId = ?").all(invoice.id);

  let subtotal = 0;
  let totalVat = 0;
  items.forEach((item) => {
    const lineAmount = item.quantity * item.unitPrice;
    subtotal += lineAmount;
    totalVat += lineAmount * (item.vatRate / 100);
  });
  const grandTotal = subtotal + totalVat;

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `attachment; filename=invoice-${invoice.invoiceNumber}.pdf`);

  const doc = new PDFDocument({ margin: 50 });
  doc.pipe(res);

  doc.fontSize(22).text(`Invoice ${invoice.invoiceNumber}`, { align: "left" });
  doc.moveDown();
  doc.fontSize(11).fillColor("#555").text(`Seller: ${invoice.sellerName}  (TRN: ${invoice.sellerTRN})`);
  doc.text(`Client: ${invoice.clientName}${invoice.clientTRN ? `  (TRN: ${invoice.clientTRN})` : ""}`);
  if (invoice.clientEmail) doc.text(`Email: ${invoice.clientEmail}`);
  doc.text(`Issue Date: ${invoice.issueDate}`);
  if (invoice.dueDate) doc.text(`Due Date: ${invoice.dueDate}`);
  doc.text(`Status: ${invoice.status.toUpperCase()}`);
  doc.moveDown();

  doc.fillColor("#000").fontSize(13).text("Items", { underline: true });
  doc.moveDown(0.5);
  items.forEach((item) => {
    const lineTotal = (item.quantity * item.unitPrice).toFixed(2);
    doc.fontSize(11).text(`${item.description}`);
    doc.fontSize(10).fillColor("#555").text(`  Qty: ${item.quantity}  x  ${item.unitPrice} ${invoice.currency}  =  ${lineTotal} ${invoice.currency}   (VAT ${item.vatRate}%)`);
    doc.fillColor("#000");
    doc.moveDown(0.3);
  });

  doc.moveDown();
  doc.fontSize(11).text(`Subtotal: ${subtotal.toFixed(2)} ${invoice.currency}`, { align: "right" });
  doc.text(`VAT: ${totalVat.toFixed(2)} ${invoice.currency}`, { align: "right" });
  doc.fontSize(14).text(`Total: ${grandTotal.toFixed(2)} ${invoice.currency}`, { align: "right" });

  doc.end();
});

app.get("/invoices/:id/xml", requireAuth, (req, res) => {
  const invoice = db.prepare("SELECT * FROM invoices WHERE id = ? AND userId = ?").get(req.params.id, req.user.userId);
  if (!invoice) {
    return res.status(404).json({ error: "Invoice not found" });
  }
  const items = db.prepare("SELECT * FROM invoice_items WHERE invoiceId = ?").all(invoice.id);

  let subtotal = 0;
  let totalVat = 0;

  const itemsXml = items.map((item, index) => {
    const lineAmount = item.quantity * item.unitPrice;
    const vatAmount = lineAmount * (item.vatRate / 100);
    subtotal += lineAmount;
    totalVat += vatAmount;
    return `
    <cac:InvoiceLine>
      <cbc:ID>${index + 1}</cbc:ID>
      <cbc:InvoicedQuantity>${item.quantity}</cbc:InvoicedQuantity>
      <cbc:LineExtensionAmount currencyID="${invoice.currency}">${lineAmount.toFixed(2)}</cbc:LineExtensionAmount>
      <cac:Item><cbc:Description>${item.description}</cbc:Description></cac:Item>
      <cac:Price><cbc:PriceAmount currencyID="${invoice.currency}">${item.unitPrice}</cbc:PriceAmount></cac:Price>
      <cac:TaxTotal><cbc:TaxAmount currencyID="${invoice.currency}">${vatAmount.toFixed(2)}</cbc:TaxAmount></cac:TaxTotal>
    </cac:InvoiceLine>`;
  }).join("");

  const grandTotal = subtotal + totalVat;

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
  <cbc:ID>${invoice.invoiceNumber}</cbc:ID>
  <cbc:IssueDate>${invoice.issueDate.split(" ")[0]}</cbc:IssueDate>
  <cbc:DueDate>${invoice.dueDate || ""}</cbc:DueDate>
  <cbc:DocumentCurrencyCode>${invoice.currency}</cbc:DocumentCurrencyCode>
  <cac:AccountingSupplierParty><cac:Party>
    <cac:PartyName><cbc:Name>${invoice.sellerName}</cbc:Name></cac:PartyName>
    <cac:PartyTaxScheme><cbc:CompanyID>${invoice.sellerTRN}</cbc:CompanyID><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:PartyTaxScheme>
  </cac:Party></cac:AccountingSupplierParty>
  <cac:AccountingCustomerParty><cac:Party>
    <cac:PartyName><cbc:Name>${invoice.clientName}</cbc:Name></cac:PartyName>
    ${invoice.clientTRN ? `<cac:PartyTaxScheme><cbc:CompanyID>${invoice.clientTRN}</cbc:CompanyID><cac:TaxScheme><cbc:ID>VAT</cbc:ID></cac:TaxScheme></cac:PartyTaxScheme>` : ""}
  </cac:Party></cac:AccountingCustomerParty>
  <cac:TaxTotal><cbc:TaxAmount currencyID="${invoice.currency}">${totalVat.toFixed(2)}</cbc:TaxAmount></cac:TaxTotal>
  <cac:LegalMonetaryTotal>
    <cbc:LineExtensionAmount currencyID="${invoice.currency}">${subtotal.toFixed(2)}</cbc:LineExtensionAmount>
    <cbc:TaxInclusiveAmount currencyID="${invoice.currency}">${grandTotal.toFixed(2)}</cbc:TaxInclusiveAmount>
    <cbc:PayableAmount currencyID="${invoice.currency}">${grandTotal.toFixed(2)}</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>
  ${itemsXml}
</Invoice>`;

  res.setHeader("Content-Type", "application/xml");
  res.setHeader("Content-Disposition", `attachment; filename=invoice-${invoice.invoiceNumber}.xml`);
  res.send(xml);
});

// ---------- NOTES (kept from before) ----------

app.get("/notes", requireAuth, (req, res) => {
  const notes = db.prepare("SELECT * FROM notes").all();
  res.json(notes);
});

app.post("/notes", requireAuth, (req, res) => {
  const text = req.body.text;
  if (!text) return res.status(400).json({ error: "Note text is required" });
  const result = db.prepare("INSERT INTO notes (text) VALUES (?)").run(text);
  res.json({ message: "Note saved!", id: result.lastInsertRowid });
});

app.delete("/notes/:id", requireAuth, (req, res) => {
  db.prepare("DELETE FROM notes WHERE id = ?").run(req.params.id);
  res.json({ message: `Note ${req.params.id} deleted` });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});