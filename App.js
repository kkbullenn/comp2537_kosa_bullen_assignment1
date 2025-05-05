require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const connectDB = require('./MongoConnector');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { hashPassword, comparePassword, schemas } = require('./Schema');

const app = express();

connectDB();
const User = require('./models/User');

app.use(session({
  secret: process.env.NODE_SESSION_SECRET,
  store: MongoStore.create({
    client: mongoose.connection.getClient(), 
    crypto: {
      secret: process.env.MONGODB_SESSION_SECRET
    }
  }), 
  resave: false,
  saveUninitialized: false,
  cookie: { 
    maxAge: 3600000, // 1 Hour
    httpOnly: true
  }
}));

app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

function getHomePage(loggedIn = false, user = null) {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Home</title>
      <link rel="stylesheet" href="/css/style.css">
    </head>
    <body>
      ${loggedIn 
        ? `<h1>Hello, ${user.name}!</h1>
           <a href="/members">Go to Members Area</a>
           <a href="/logout">Sign out</a>`
        : `<h1>Welcome</h1>
           <a href="/signup">Sign up</a>
           <a href="/login">Log in</a>`}
    </body>
    </html>
  `;
}

function getSignupPage(error = null) {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Sign Up</title>
      <link rel="stylesheet" href="/css/style.css">
    </head>
    <body>
      <h1>Create User</h1>
      ${error ? `<p class="error">${error}</p>` : ''}
      <form action="/signupSubmit" method="POST">
        <label>Name: <input type="text" name="name" required></label>
        <label>Email: <input type="email" name="email" required></label>
        <label>Password: <input type="password" name="password" required minlength="6"></label>
        <button type="submit">Submit</button>
      </form>
      <a href="/">Back to Home</a>
    </body>
    </html>
  `;
}

function getLoginPage(error = null, preservedEmail = '') {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Login</title>
      <link rel="stylesheet" href="/css/style.css">
    </head>
    <body>
      <h1>Login</h1>
      ${error ? `<p class="error">${error}</p>` : ''}
      <form action="/loginSubmit" method="POST">
        <label>Email: <input type="email" name="email" value="${preservedEmail}" required></label>
        <label>Password: <input type="password" name="password" required></label>
        <button type="submit">Login</button>
      </form>
      <a href="/">Back to Home</a>
    </body>
    </html>
  `;
}

app.get('/', (req, res) => {
  if (req.session.user) {
    res.send(getHomePage(true, req.session.user));
  } else {
    res.send(getHomePage(false));
  }
});

app.get('/signup', (req, res) => {
  res.send(getSignupPage());
});

app.get('/login', (req, res) => {
  res.send(getLoginPage());
});

app.post('/signupSubmit', async (req, res) => {
  try {
  
    const newUser = new User({
      name: req.body.name,
      email: req.body.email,
      password: req.body.password 
    });
    
    await newUser.save(); 
    
    req.session.user = {
      id: newUser._id,
      name: newUser.name,
      email: newUser.email
    };
    
    res.redirect('/members');
  } catch (err) {
    console.error('Signup error:', err);
    res.send(getSignupPage(err.message));
  }
});

app.post('/loginSubmit', async (req, res) => {
  const { email, password } = req.body;
  const { error } = schemas.login.validate({ email, password });
  
  if (error) {
    const errorMessage = error.details[0].context.label === 'email' 
      ? 'Invalid email format' 
      : 'Password is required';
    return res.send(getLoginPage(errorMessage));
  }

  try {
    const user = await User.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });
    if (!user) {
      return res.send(getLoginPage('Email not found'));
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.send(getLoginPage('Incorrect password'));
    }

    req.session.user = {
      id: user._id,
      name: user.name,
      email: user.email
    };
    
    res.redirect('/members');
  } catch (err) {
    console.error('Login error:', err);
    res.send(getLoginPage('An error occurred during login'));
  }
});

app.get('/members', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  
  const randomImage = Math.floor(Math.random() * 3) + 1;
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Members Area</title>
      <link rel="stylesheet" href="/css/style.css">
    </head>
    <body>
      <h1>Hello, ${req.session.user.name}!</h1>
      <img src="/images/image${randomImage}.jpg" alt="Random image">
      <a href="/logout">Sign out</a>
      <a href="/">Back to Home</a>
    </body>
    </html>
  `);
});

app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Logout error:', err);
    }
    res.redirect('/');
  });
});

app.use((req, res) => {
  res.status(404);
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>404 Not Found</title>
      <link rel="stylesheet" href="/css/style.css">
    </head>
    <body>
      <h1>Page not found - 404</h1>
      <a href="/">Return home</a>
    </body>
    </html>
  `);
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});