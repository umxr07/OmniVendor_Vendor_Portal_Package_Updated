require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs'); // Used only to allow old accounts to keep working.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const TOKEN_SECRET = process.env.TOKEN_SECRET || '';
if (!ADMIN_EMAIL || !ADMIN_PASSWORD || !TOKEN_SECRET) {
  console.error('Set ADMIN_EMAIL, ADMIN_PASSWORD and TOKEN_SECRET in .env before starting.');
  process.exit(1);
}

const DATA_FILE = path.join(__dirname, 'data.json');
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

let state = {
  initialized: false,
  data: { categories: [], vendors: [], items: [], purchaseOrders: [], notifications: [] },
  accounts: []
};
try {
  if (fs.existsSync(DATA_FILE)) {
    const saved = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    state = { ...state, ...saved };
    state.data = { ...state.data, ...(saved.data || {}) };
    state.accounts = Array.isArray(saved.accounts) ? saved.accounts : [];
  }
} catch (e) {
  console.error('Could not read data.json:', e.message);
}
// A vendor may register before the admin portal has uploaded its catalogue.
// In that case, let the admin's first sync seed the shared data instead of
// treating the registration-only state as a complete portal database.
if (state.accounts.length && state.data.categories.length === 0 && state.data.items.length === 0 && state.data.purchaseOrders.length === 0) {
  state.initialized = false;
}
function persist() {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(state, null, 2));
  fs.renameSync(tmp, DATA_FILE);
}
function safeData() { return state.data; }
function signToken(payload) {
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + 12 * 60 * 60 * 1000 })).toString('base64url');
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(body).digest('base64url');
  return body + '.' + sig;
}
function readToken(req) {
  const raw = String(req.get('authorization') || '').replace(/^Bearer\s+/i, '');
  const parts = raw.split('.');
  if (parts.length !== 2) return null;
  const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(parts[0]).digest('base64url');
  if (sig.length !== parts[1].length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(parts[1]))) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}
function adminOnly(req, res, next) {
  const payload = readToken(req);
  if (!payload || payload.role !== 'admin') return res.status(401).json({ error: 'Please sign in as admin' });
  next();
}
function vendorAuth(req, res, next) {
  const payload = readToken(req);
  if (!payload || payload.role !== 'vendor') return res.status(401).json({ error: 'Please sign in again' });
  const account = state.accounts.find(a => a.vendorId === payload.sub);
  const vendor = state.data.vendors.find(v => v.id === payload.sub);
  if (!account || !vendor) return res.status(401).json({ error: 'Vendor account unavailable' });
  if (vendor.status === 'Rejected') return res.status(403).json({ error: 'Your vendor registration was rejected.' });
  req.vendor = vendor;
  req.account = account;
  next();
}
const validEmail = value => /^\S+@\S+\.\S+$/.test(String(value || ''));
const validStatuses = ['Pending', 'Accepted', 'Approved', 'Processing', 'Shipped', 'Mark Shipped', 'Received Delivery', 'Fulfilled', 'Rejected'];

app.get('/api/health', (req, res) => res.json({ ok: true, initialized: state.initialized }));

app.post('/api/admin/login', (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Invalid admin email or password' });
  res.json({ token: signToken({ sub: 'admin', email: ADMIN_EMAIL, role: 'admin' }) });
});

app.get('/api/admin/data', adminOnly, (req, res) => res.json({ initialized: state.initialized, data: safeData() }));
app.put('/api/admin/data', adminOnly, (req, res) => {
  const d = req.body?.data;
  if (!d || !Array.isArray(d.vendors) || !Array.isArray(d.purchaseOrders) || !Array.isArray(d.items) || !Array.isArray(d.categories))
    return res.status(400).json({ error: 'Invalid portal data' });
  // Link self-registered accounts to existing admin vendor records by email.
  // This also repairs accounts registered before the admin catalogue was synced.
  for (const account of state.accounts) {
    const matchingVendor = d.vendors.find(v => String(v.email || '').trim().toLowerCase() === String(account.email || '').trim().toLowerCase());
    if (matchingVendor) account.vendorId = matchingVendor.id;
  }
  // Keep account-linked vendors even if an old local cache hasn't received a new registration yet.
  const mergedVendors = [...d.vendors];
  for (const existing of state.data.vendors) {
    if (state.accounts.some(a => a.vendorId === existing.id) && !mergedVendors.some(v => v.id === existing.id)) mergedVendors.push(existing);
  }
  state.data = {
    categories: d.categories,
    vendors: mergedVendors,
    items: d.items,
    purchaseOrders: d.purchaseOrders,
    notifications: Array.isArray(d.notifications) ? d.notifications : []
  };
  state.initialized = true;
  for (const a of state.accounts) {
    const v = state.data.vendors.find(x => x.id === a.vendorId);
    if (v) a.email = String(v.email || a.email).toLowerCase();
  }
  persist();
  res.json({ ok: true, data: state.data });
});

app.post('/api/vendor/register', (req, res) => {
  const name = String(req.body?.name || '').trim();
  const email = String(req.body?.email || '').trim().toLowerCase();
  const phone = String(req.body?.phone || '').trim();
  const password = String(req.body?.password || '');
  const category = String(req.body?.category || 'General').trim();
  if (!name || !validEmail(email) || password.length < 1) return res.status(400).json({ error: 'Enter a business name, valid email and password.' });
  if (state.accounts.some(a => String(a.email).toLowerCase() === email)) return res.status(409).json({ error: 'An account with this email already exists.' });
  const categoryObj = state.data.categories.find(c => String(c.name).toLowerCase() === category.toLowerCase());
  // Reuse an existing admin vendor with the same email so its purchase orders appear.
  let vendor = state.data.vendors.find(v => String(v.email || '').trim().toLowerCase() === email);
  if (vendor) {
    vendor.phone = phone || vendor.phone || '';
    if (!vendor.categoryId && categoryObj) vendor.categoryId = categoryObj.id;
  } else {
    const vendorId = 'v-' + Date.now() + '-' + crypto.randomBytes(3).toString('hex');
    vendor = {
      id: vendorId, name, email, phone, categoryId: categoryObj?.id || '',
      rating: 5, status: 'Active', contactPerson: '', address: '', gstNumber: ''
    };
    state.data.vendors.push(vendor);
  }
  // Simple-project mode requested: store the password as plain text in data.json.
  state.accounts.push({ vendorId: vendor.id, email, password });
  state.data.notifications.unshift({
    id: 'n-' + Date.now(), title: 'Vendor Self-Registered',
    text: `${name} created a vendor account.`, time: 'Just now', unread: true
  });
  persist();
  res.status(201).json({ ok: true, message: 'Registration successful. You can now sign in.' });
});

app.post('/api/vendor/login', async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  const account = state.accounts.find(a => String(a.email || '').toLowerCase() === email);
  let valid = false;
  if (account) {
    if (typeof account.password === 'string') valid = account.password === password;
    else if (account.passwordHash) {
      try { valid = await bcrypt.compare(password, account.passwordHash); } catch {}
    }
  }
  if (!valid) return res.status(401).json({ error: 'Email or password is incorrect' });
  const vendor = state.data.vendors.find(v => v.id === account.vendorId);
  if (!vendor) return res.status(401).json({ error: 'Vendor account unavailable' });
  if (vendor.status === 'Rejected') return res.status(403).json({ error: 'Your vendor registration was rejected.' });
  res.json({ token: signToken({ sub: account.vendorId, email: account.email, role: 'vendor' }) });
});

app.get('/api/vendor/me', vendorAuth, (req, res) => {
  const vendor = req.vendor;
  res.json({
    vendor,
    orders: state.data.purchaseOrders.filter(o => o.vendorId === vendor.id),
    items: state.data.items.filter(i => i.vendorId === vendor.id)
  });
});

app.patch('/api/vendor/orders/:id', vendorAuth, (req, res) => {
  const po = state.data.purchaseOrders.find(o => o.id === req.params.id && o.vendorId === req.vendor.id);
  if (!po) return res.status(404).json({ error: 'Order not found' });
  const next = String(req.body?.status || '');
  const transitions = {
    Pending: ['Approved', 'Rejected'], Accepted: ['Processing', 'Rejected'],
    Approved: ['Mark Shipped', 'Rejected', 'Processing'], Processing: ['Shipped', 'Mark Shipped'],
    Shipped: ['Received Delivery'], 'Mark Shipped': ['Received Delivery'],
    'Received Delivery': ['Fulfilled'], Fulfilled: [], Rejected: []
  };
  if (!(transitions[po.status] || []).includes(next)) return res.status(400).json({ error: `Cannot change ${po.status} to ${next}` });
  if (next === 'Fulfilled' && !po.stockReceived) {
    const item = state.data.items.find(i => i.id === po.itemId);
    if (item) item.stock = Number(item.stock || 0) + Number(po.quantity || 0);
    po.stockReceived = true;
  }
  po.status = next;
  state.data.notifications.unshift({
    id: 'n-' + Date.now(), title: 'Vendor Order Update',
    text: `${req.vendor.name} updated ${po.id} to ${next}.`, time: 'Just now', unread: true
  });
  state.initialized = true;
  persist();
  res.json({ ok: true, order: po });
});

app.put('/api/vendor/profile', vendorAuth, (req, res) => {
  const { name, email, phone, contactPerson, address, gstNumber } = req.body || {};
  if (!String(name || '').trim() || !validEmail(email)) return res.status(400).json({ error: 'Business name and valid email are required' });
  const newEmail = String(email).trim().toLowerCase();
  if (state.accounts.some(a => String(a.email).toLowerCase() === newEmail && a.vendorId !== req.vendor.id))
    return res.status(409).json({ error: 'Email is already used by another vendor' });
  Object.assign(req.vendor, {
    name: String(name).trim(), email: newEmail, phone: String(phone || '').trim(),
    contactPerson: String(contactPerson || '').trim(), address: String(address || '').trim(),
    gstNumber: String(gstNumber || '').trim()
  });
  req.account.email = newEmail;
  state.data.notifications.unshift({
    id: 'n-' + Date.now(), title: 'Vendor Profile Updated',
    text: `${req.vendor.name} updated business profile details.`, time: 'Just now', unread: true
  });
  persist();
  res.json({ ok: true });
});

app.get('/admin-login.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin-login.html')));
app.get('/vendor.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'vendor.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin-login.html')));
app.listen(PORT, () => console.log(`OmniVendor running at http://localhost:${PORT}\nAdmin: http://localhost:${PORT}/admin-login.html\nVendor: http://localhost:${PORT}/vendor.html`));
