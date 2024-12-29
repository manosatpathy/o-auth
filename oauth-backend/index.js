const express = require("express");
const axios = require("axios");
const cors = require("cors");
const { setSecureCookie } = require("./services/index");
const cookieParser = require("cookie-parser");
const { verifyAccessToken } = require("./middleware/index.js");

require("dotenv").config();
const app = express();
const PORT = process.env.PORT || 4000;
app.use(cors({ credentials: true, origin: "http://localhost:3000" }));
app.use(cookieParser());

app.get("/", (req, res) => {
  res.send(`<h1>Welcome to OAuth API Server <h1>`);
});

//PROTECTED ROUTES
app.get("/user/profile/github", verifyAccessToken, async (req, res) => {
  try {
    const { access_token } = req.cookies;
    const githubUserDataResponse = await axios.get(
      "https://api.github.com/user",
      {
        headers: {
          Authorization: `Bearer ${access_token}`,
        },
      }
    );
    res.json({ user: githubUserDataResponse.data });
  } catch (err) {
    res.status(500).json({ error: "Could not fetch user's github Profile" });
  }
});

app.get("/user/profile/google", verifyAccessToken, async (req, res) => {
  try {
    const { access_token } = req.cookies;
    const googleUserDataResponse = await axios.get(
      "https://www.googleapis.com/oauth2/v2/userinfo",
      {
        headers: {
          Authorization: `Bearer ${access_token}`,
        },
      }
    );
    console.log(googleUserDataResponse.data);
    res.json({ user: googleUserDataResponse.data });
  } catch (err) {
    res.status(500).json({ error: "Could not fetch user's google Profile" });
  }
});

app.get("/auth/github", (req, res) => {
  const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${process.env.GITHUB_CLIENT_ID}&scope=user,repo,security_events`;
  res.redirect(githubAuthUrl);
});

app.get("/auth/github/callback", async (req, res) => {
  const { code } = req.query;
  if (!code) {
    return res.status(400).send("Authrization code not provided");
  }
  try {
    const tokenResponse = await axios.post(
      "https://github.com/login/oauth/access_token",
      {
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code,
      },
      {
        headers: { Accept: "application/json" },
      }
    );
    const accessToken = tokenResponse.data.access_token;
    setSecureCookie(res, accessToken);
    return res.redirect(`${process.env.FRONTEND_URL}/v2/profile/github`);
  } catch (err) {
    res.status(500).json(err);
  }
});

//GOOGLE OAUTH

app.get("/auth/google", (req, res) => {
  const googleAuthUrl = `https://accounts.google.com/o/oauth2/auth?client_id=${process.env.GOOGLE_CLIENT_ID}&redirect_uri=http://localhost:${PORT}/auth/google/callback&response_type=code&scope=profile email`;
  res.redirect(googleAuthUrl);
});

app.get("/auth/google/callback", async (req, res) => {
  const { code } = req.query;
  if (!code) {
    return res.status(400).send("Authrization code not provided");
  }
  let accessToken;
  try {
    const tokenResponse = await axios.post(
      "https://oauth2.googleapis.com/token",
      {
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        code,
        grant_type: "authorization_code",
        redirect_uri: `http://localhost:${PORT}/auth/google/callback`,
      },
      {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      }
    );
    accessToken = tokenResponse.data.access_token;
    setSecureCookie(res, accessToken);
    return res.redirect(`${process.env.FRONTEND_URL}/v2/profile/google`);
  } catch (err) {
    console.error(err);
  }
});

app.listen(PORT, () => {
  console.log("Server is running on port " + PORT);
});
