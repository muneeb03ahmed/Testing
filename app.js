const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/vulnerableApp', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.log('Error connecting to MongoDB', err));

// User Schema
const User = require('./models/user');

// Routes

// Home route (Sign Up and Login)
app.get('/', (req, res) => {
  res.render('index');
});

// Sign Up route
app.post('/signup', (req, res) => {
  const { username, password } = req.body;

  // Vulnerability: SQL Injection
  const user = new User({
    username: username,
    password: password
  });

  user.save((err) => {
    if (err) {
      res.status(500).send('Error saving user');
    } else {
      res.redirect('/login');
    }
  });
});

// Login route
app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Vulnerability: SQL Injection
  User.findOne({ username: username, password: password }, (err, user) => {
    if (err) {
      res.status(500).send('Error logging in');
    } else if (!user) {
      res.send('Invalid credentials');
    } else {
      res.redirect(`/profile/${user._id}`);
    }
  });
});

// Profile route (XSS vulnerability)
app.get('/profile/:id', (req, res) => {
  const userId = req.params.id;

  // Vulnerability: XSS (Reflective XSS)
  User.findById(userId, (err, user) => {
    if (err || !user) {
      res.status(404).send('User not found');
    } else {
      res.render('profile', { user });
    }
  });
});

// Command injection route (vulnerable endpoint)
app.get('/system', (req, res) => {
  const { cmd } = req.query;

  // Vulnerability: Command Line Injection
  const exec = require('child_process').exec;
  exec(cmd, (err, stdout, stderr) => {
    if (err) {
      res.status(500).send('Error executing command');
    } else {
      res.send(`<pre>${stdout}</pre>`);
    }
  });
});

// Start the server
app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
