const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json()); // to parse JSON bodies

// MySQL Database Connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',       // your MySQL username
  password: '',       // your MySQL password
  database: 'subscriptions_system'  // your database name
});

db.connect((err) => {
  if (err) throw err;
  console.log('Connected to MySQL database!');
});

// Endpoint for User Registration
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Insert into the database
  const query = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
  db.query(query, [name, email, hashedPassword], (err, results) => {
    if (err) return res.status(500).json({ message: 'Error registering user' });
    res.status(201).json({ message: 'User registered successfully' });
  });
});

// Endpoint for User Login
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  // Check if user exists
  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err || results.length === 0) return res.status(400).json({ message: 'User not found' });

    // Compare password with the hashed password
    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    // Generate JWT Token
    const token = jwt.sign({ id: user.id, email: user.email }, 'your-secret-key', { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
  });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
