const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();

app.use(cors());
app.use(express.json());


const users = [];
const JWT_SECRET = 'your_jwt_secret';

//to authenticate JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401); // No token,unauthorized

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // Invalid token
    req.user = user;
    next();
  });
};

//Register new user
app.post('/register', async (req, res) => {
  const { firstName, lastName, email, password, phoneNumber } = req.body;

  // Check if an user exist already
  if (users.some(u => u.email === email)) {
    return res.status(400).json({ message: 'User already exists' });
  }

  //Hash password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Create a new user object
  const user = {
    id: users.length + 1,
    email,
    password: hashedPassword,
    firstName: firstName || null,
    lastName: lastName || null,
    phoneNumber: phoneNumber || null
  };

  // Add the user to database
  users.push(user);
  res.status(201).json({ message: 'User registered successfully' });
});

// Login a user
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  // Generate JWT token
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// List all users
app.get('/users', authenticateToken, (req, res) => {
  const usersWithoutPasswords = users.map(({ password, ...user }) => user);
  res.json(usersWithoutPasswords);
});

// View specific user details
app.get('/users/:id', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.status(404).json({ message: 'User not found' });

  const { password, ...userWithoutPassword } = user;
  res.json(userWithoutPassword);
});

// Start server
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
