'use strict';

const express = require('express');
const cookieParser = require('cookie-parser');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const PAGE_STYLE = `
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #111;
    color: #fff;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .card {
    background: #1a1a1a;
    border-radius: 16px;
    padding: 40px;
    width: 100%;
    max-width: 420px;
    border: 1px solid #333;
  }
  .logo {
    text-align: center;
    margin-bottom: 32px;
  }
  .logo h1 {
    font-size: 24px;
    font-weight: 700;
    color: #fff;
  }
  .logo p {
    font-size: 14px;
    color: #888;
    margin-top: 8px;
  }
  label {
    display: block;
    font-size: 13px;
    font-weight: 500;
    color: #888;
    margin-bottom: 6px;
  }
  input[type="email"], input[type="text"], input[type="password"] {
    width: 100%;
    padding: 12px 14px;
    background: #111;
    border: 1px solid #333;
    border-radius: 8px;
    color: #fff;
    font-size: 15px;
    margin-bottom: 20px;
    transition: border-color 0.2s;
  }
  input:focus {
    outline: none;
    border-color: #666;
  }
  button {
    width: 100%;
    padding: 13px;
    background: #fff;
    color: #000;
    border: none;
    border-radius: 8px;
    font-size: 15px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.2s;
  }
  button:hover { background: #ddd; }
  .dashboard-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 24px;
  }
  .avatar {
    width: 48px;
    height: 48px;
    background: #fff;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
    font-weight: 700;
    color: #000;
  }
  .welcome { font-size: 28px; font-weight: 700; margin-bottom: 8px; }
  .subtitle { color: #888; font-size: 15px; }
  .logout-btn {
    background: transparent;
    border: 1px solid #333;
    color: #888;
    margin-top: 8px;
  }
  .logout-btn:hover { background: #222; color: #fff; }
`;

app.get('/', (req, res) => {
  if (req.cookies.session) {
    return res.redirect('/dashboard');
  }

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login - AuthSignal Demo</title>
  <style>${PAGE_STYLE}</style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <h1>Authsignal demo</h1>
      <p>Adaptive MFA with Lambda@Edge</p>
    </div>
    <form method="POST" action="/login/password">
      <label for="username">Email</label>
      <input type="email" id="username" name="username" placeholder="Enter your email" required autofocus>
      <label for="password">Password</label>
      <input type="password" id="password" name="password" placeholder="Enter any password" required>
      <button type="submit">Sign In</button>
    </form>
  </div>
</body>
</html>`);
});

app.post('/login/password', (req, res) => {
  const { username, password } = req.body;

  if (!username) {
    return res.status(400).send('Username is required');
  }

  console.log(`[origin] Login for user: ${username}`);

  res.cookie('session', username, {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    maxAge: 3600000,
  });
  res.redirect('/dashboard');
});

app.get('/login/password', (_req, res) => {
  res.redirect('/');
});

app.get('/dashboard', (req, res) => {
  const username = req.cookies.session;
  if (!username) {
    return res.redirect('/');
  }

  const initial = username.charAt(0).toUpperCase();

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Dashboard - AuthSignal Demo</title>
  <style>${PAGE_STYLE}</style>
</head>
<body>
  <div class="card" style="max-width: 480px;">
    <div class="dashboard-header">
      <div>
        <div class="welcome">Welcome back!</div>
        <div class="subtitle">You're signed in as <strong>${username}</strong></div>
      </div>
      <div class="avatar">${initial}</div>
    </div>
    <form method="POST" action="/logout">
      <button type="submit" class="logout-btn">Sign Out</button>
    </form>
  </div>
</body>
</html>`);
});

app.post('/logout', (_req, res) => {
  res.clearCookie('session');
  res.redirect('/');
});

const serverlessExpress = require('@vendia/serverless-express');
exports.handler = serverlessExpress({ app });

if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`Demo app running at http://localhost:${port}`);
  });
}
