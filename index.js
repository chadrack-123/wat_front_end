const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const db = new sqlite3.Database('users.db');

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, 'public')));

// Signup route
app.post('/signup', async (req, res) => {
    const { email, password } = req.body;  // Removed username from the request body
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run('INSERT INTO users (email, password) VALUES (?, ?)',
        [email, hashedPassword], function (err) {
        if (err) {
            return res.status(500).json({ error: 'User already exists or database error' });
        }
        res.status(201).json({ message: 'User created successfully' });
    });
});

// Login route
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        // Send the redirect URL in the response
        res.status(200).json({ message: 'Logged in successfully', redirect: '/dashboard' });
        
    });
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/logout', (req, res) => {
    // If using sessions, you would destroy the session here
    // req.session.destroy(err => {
    //     if (err) {
    //         return res.redirect('/dashboard');
    //     }
    //     res.clearCookie('sessionId');
    //     res.redirect('/login');
    // });

    // For simplicity, just redirect to login
    res.redirect('/login.html');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
