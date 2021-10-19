import express from "express";
import jwt from "jsonwebtoken";
import crypto from "crypto";

// This makes a very secure random secret with every app reboot
const secret = crypto.randomBytes(64).toString("hex");
console.log({ secret });

// This middleware can be used to check if a reqest contains a valid token
function checkTokenMiddleware(req, res, next) {
  const tokenRaw = req.headers.authorization;
  console.log(`Token raw is: "${tokenRaw}""`);
  if (!tokenRaw) {
    return res.sendStatus(401);
  }

  const tokenToCheck = tokenRaw.split(" ")[1];
  console.log(`Token to check is: "${tokenToCheck}"`);
  if (!tokenToCheck) {
    return res.sendStatus(401);
  }

  jwt.verify(tokenToCheck, secret, (error, payload) => {
    console.log({ error, payload });

    if (error) {
      return res.status(400).send(error.message);
    }

    req.userData = {
      userId: payload.userId,
      username: payload.username,
      admin: payload.admin,
    };
    next();
  });
}

// Setup Express application
const app = express();

// This endpoint returns a fresh token
app.get("/token", (req, res) => {
  // TODO: Check login username / password somehow
  const payload = { userId: 42, username: "Veera cat", admin: true };
  const options = { expiresIn: "5m" };
  const token = jwt.sign(payload, secret, options);
  res.send(token);
});

// This endpoint is secured; only requests with a valid token can access ot
app.get("/secure", checkTokenMiddleware, (req, res) => {
  // check token and return something
  res.send(`Hooray, ${req.userData.username}, you have access`);
});

const port = 8000;
app.listen(port, () => {
  console.log("Listening on http://localhost:" + port);
});
