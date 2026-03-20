const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const cors    = require('cors');

const app        = express();
const PORT       = 3000;
const SECRET_KEY = 'your-very-secure-secret';

app.use(cors({
  origin: ['http://127.0.0.1:5500', 'http://localhost:5500']
}));
app.use(express.json());

const db = {
  accounts: [
    {
      id:        'admin-uuid-001',
      firstName: 'Admin',
      lastName:  'User',
      email:     'admin@example.com',
      password:  '',         
      role:      'admin',
      verified:  true
    }
  ],
  departments: [
    { id: 'dept-uuid-001', name: 'Engineering', description: 'Builds stuff' },
    { id: 'dept-uuid-002', name: 'HR',          description: 'People ops'   },
    { id: 'dept-uuid-003', name: 'IT',          description: 'Technology Dept' }
  ],
  employees: [],
  requests:  []
};

(async () => {
  db.accounts[0].password = await bcrypt.hash('Password123!', 10);
  console.log('✅ Default admin password hashed.');
})();

function makeId() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

function safeAccount(a) {
  const { password, ...safe } = a;
  return safe;
}

app.post('/api/register', async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  if (!firstName || !lastName || !email || !password)
    return res.status(400).json({ error: 'All fields are required.' });

  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  const emailLc = email.trim().toLowerCase();
  if (db.accounts.some(a => a.email === emailLc))
    return res.status(409).json({ error: 'Email already registered.' });

  const hashed = await bcrypt.hash(password, 10);
  const newAccount = {
    id:        makeId(),
    firstName: firstName.trim(),
    lastName:  lastName.trim(),
    email:     emailLc,
    password:  hashed,
    role:      'user',
    verified:  false
  };

  db.accounts.push(newAccount);
  res.status(201).json({ message: 'Registered. Please verify your email.', email: emailLc });
});

app.post('/api/verify-email', (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const acc   = db.accounts.find(a => a.email === email);

  if (!acc)            return res.status(404).json({ error: 'Account not found.' });
  if (acc.verified)    return res.json({ message: 'Already verified.' });

  acc.verified = true;
  res.json({ message: 'Email verified. You can now log in.' });
});

app.post('/api/login', async (req, res) => {
  const email    = (req.body.email || '').trim().toLowerCase();
  const password = req.body.password || '';

  const acc = db.accounts.find(a => a.email === email);

  if (!acc || !(await bcrypt.compare(password, acc.password)))
    return res.status(401).json({ error: 'Invalid credentials.' });

  if (!acc.verified)
    return res.status(403).json({ error: 'Email not verified.' });

  const token = jwt.sign(
    { id: acc.id, email: acc.email, firstName: acc.firstName, lastName: acc.lastName, role: acc.role },
    SECRET_KEY,
    { expiresIn: '2h' }
  );

  res.json({ token, user: safeAccount(acc) });
});

app.get('/api/profile', authenticateToken, (req, res) => {
  const acc = db.accounts.find(a => a.id === req.user.id);
  if (!acc) return res.status(404).json({ error: 'User not found.' });
  res.json({ user: safeAccount(acc) });
});

app.put('/api/profile', authenticateToken, async (req, res) => {
  const acc = db.accounts.find(a => a.id === req.user.id);
  if (!acc) return res.status(404).json({ error: 'User not found.' });

  const { firstName, lastName } = req.body;
  if (firstName && firstName.trim().length >= 2) acc.firstName = firstName.trim();
  if (lastName  && lastName.trim().length  >= 2) acc.lastName  = lastName.trim();

  res.json({ message: 'Profile updated.', user: safeAccount(acc) });
});

app.get('/api/accounts', authenticateToken, authorizeRole('admin'), (req, res) => {
  res.json(db.accounts.map(safeAccount));
});

app.post('/api/accounts', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const { firstName, lastName, email, password, role = 'user', verified = false } = req.body;

  if (!firstName || !lastName || !email || !password)
    return res.status(400).json({ error: 'All fields required.' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  const emailLc = email.trim().toLowerCase();
  if (db.accounts.some(a => a.email === emailLc))
    return res.status(409).json({ error: 'Email already registered.' });

  const newAcc = {
    id:        makeId(),
    firstName: firstName.trim(),
    lastName:  lastName.trim(),
    email:     emailLc,
    password:  await bcrypt.hash(password, 10),
    role,
    verified:  !!verified
  };

  db.accounts.push(newAcc);
  res.status(201).json(safeAccount(newAcc));
});

app.put('/api/accounts/:id', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const acc = db.accounts.find(a => a.id === req.params.id);
  if (!acc) return res.status(404).json({ error: 'Account not found.' });

  const { firstName, lastName, email, password, role, verified } = req.body;

  if (firstName)             acc.firstName = firstName.trim();
  if (lastName)              acc.lastName  = lastName.trim();
  if (email)                 acc.email     = email.trim().toLowerCase();
  if (role)                  acc.role      = role;
  if (verified !== undefined) acc.verified  = !!verified;
  if (password) {
    if (password.length < 6)
      return res.status(400).json({ error: 'Password too short.' });
    acc.password = await bcrypt.hash(password, 10);
  }

  res.json(safeAccount(acc));
});

app.put('/api/accounts/:id/reset-password', authenticateToken, authorizeRole('admin'), async (req, res) => {
  const acc = db.accounts.find(a => a.id === req.params.id);
  if (!acc) return res.status(404).json({ error: 'Account not found.' });

  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  acc.password = await bcrypt.hash(newPassword, 10);
  res.json({ message: 'Password reset successfully.' });
});

app.delete('/api/accounts/:id', authenticateToken, authorizeRole('admin'), (req, res) => {
  if (req.params.id === req.user.id)
    return res.status(400).json({ error: 'You cannot delete your own account.' });

  const idx = db.accounts.findIndex(a => a.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Account not found.' });

  db.accounts.splice(idx, 1);
  res.json({ message: 'Account deleted.' });
});

app.get('/api/departments', authenticateToken, (req, res) => {
  res.json(db.departments);
});

app.post('/api/departments', authenticateToken, authorizeRole('admin'), (req, res) => {
  const { name, description = '' } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required.' });

  const dept = { id: makeId(), name: name.trim(), description: description.trim() };
  db.departments.push(dept);
  res.status(201).json(dept);
});

app.put('/api/departments/:id', authenticateToken, authorizeRole('admin'), (req, res) => {
  const dept = db.departments.find(d => d.id === req.params.id);
  if (!dept) return res.status(404).json({ error: 'Department not found.' });

  if (req.body.name)                    dept.name        = req.body.name.trim();
  if (req.body.description !== undefined) dept.description = req.body.description.trim();
  res.json(dept);
});

app.delete('/api/departments/:id', authenticateToken, authorizeRole('admin'), (req, res) => {
  const idx = db.departments.findIndex(d => d.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Department not found.' });

  db.departments.splice(idx, 1);
  res.json({ message: 'Department deleted.' });
});


app.get('/api/employees', authenticateToken, authorizeRole('admin'), (req, res) => {
  res.json(db.employees);
});

app.post('/api/employees', authenticateToken, authorizeRole('admin'), (req, res) => {
  const { employeeId, email, position, deptId, hireDate = '' } = req.body;

  if (!employeeId || !email || !position || !deptId)
    return res.status(400).json({ error: 'All fields required.' });

  const emailLc = email.trim().toLowerCase();
  if (!db.accounts.some(a => a.email === emailLc))
    return res.status(404).json({ error: 'That email is not registered in Accounts.' });

  if (!db.departments.some(d => d.id === deptId))
    return res.status(404).json({ error: 'Department not found.' });

  const emp = { id: makeId(), employeeId: employeeId.trim(), email: emailLc, position: position.trim(), deptId, hireDate };
  db.employees.push(emp);
  res.status(201).json(emp);
});

app.put('/api/employees/:id', authenticateToken, authorizeRole('admin'), (req, res) => {
  const emp = db.employees.find(e => e.id === req.params.id);
  if (!emp) return res.status(404).json({ error: 'Employee not found.' });

  const { employeeId, email, position, deptId, hireDate } = req.body;
  if (employeeId) emp.employeeId = employeeId.trim();
  if (email)      emp.email      = email.trim().toLowerCase();
  if (position)   emp.position   = position.trim();
  if (deptId)     emp.deptId     = deptId;
  if (hireDate)   emp.hireDate   = hireDate;
  res.json(emp);
});

app.delete('/api/employees/:id', authenticateToken, authorizeRole('admin'), (req, res) => {
  const idx = db.employees.findIndex(e => e.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Employee not found.' });

  db.employees.splice(idx, 1);
  res.json({ message: 'Employee deleted.' });
});

app.get('/api/requests', authenticateToken, (req, res) => {
  if (req.user.role === 'admin') return res.json(db.requests);
  res.json(db.requests.filter(r => r.employeeEmail === req.user.email));
});

app.post('/api/requests', authenticateToken, (req, res) => {
  const { type, items } = req.body;
  if (!type || !Array.isArray(items) || items.length === 0)
    return res.status(400).json({ error: 'Type and at least one item required.' });

  const validItems = items.filter(i => i.name && i.name.trim());
  if (validItems.length === 0)
    return res.status(400).json({ error: 'Add at least 1 valid item.' });

  const request = {
    id:            makeId(),
    employeeEmail: req.user.email,
    date:          new Date().toLocaleDateString(),
    type,
    items:         validItems,
    status:        'Pending'
  };

  db.requests.push(request);
  res.status(201).json(request);
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token      = authHeader && authHeader.split(' ')[1]; 

  if (!token) return res.status(401).json({ error: 'Access token required.' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
    req.user = user;
    next();
  });
}

function authorizeRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role)
      return res.status(403).json({ error: 'Access denied: insufficient permissions.' });
    next();
  };
}

app.listen(PORT, () => {
  console.log(`\n✅ Backend running on http://localhost:${PORT}`);
  console.log(`\n🔑 Default login:`);
  console.log(`   Email:    admin@example.com`);
  console.log(`   Password: Password123!\n`);
});