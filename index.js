import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import dotenv from "dotenv";

// Read environment variables from .env
dotenv.config();

// Setup Express application
const app = express();
app.use(express.json());

// This function simply hashes a password
async function hash(password) {
  return await bcrypt.hash(password, 3);
}

// This function checks if the given password matches the given hash
async function compareHashes(password, hash) {
  return await bcrypt.compare(password, hash)
}

// This acts as a "database" for users (notice how the passwords are hashed!)
const users = [
  { username: "joel", password: await hash("12345") },
  { username: "veera", password: await hash("123456") },
  { username: "rauli", password: await hash("1234567") },
]

// This middleware can be used to check if a reqest contains a valid token
function checkTokenMiddleware(req, res, next) {
  const tokenRaw = req.headers.authorization;
  if (!tokenRaw) { return res.status(401).send("Missing authorization header"); }

  const tokenToCheck = tokenRaw.split(" ")[1];
  if (!tokenToCheck) { return res.status(401).send("Invalid authorization token"); }

  jwt.verify(tokenToCheck, process.env.SECRET, (error, payload) => {
    if (error) { return res.status(400).send(error.message); }

    req.user = { username: payload.username };
    next();
  });
}

// This endpoint is used to register a new user
app.post("/register", async (req,res) => {
  const { username, password } = req.body;

  if (users.find(x => x.username === username)) {
    res.status(400).send("username already in use");
  }
  users.push({ username, password: await hash(password) });

  res.send("registration complete, welcome aboard");
})

// This endpoint returns a fresh token
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) { return res.status(401).send("No such user"); }

  const passwordOk = await compareHashes(password, user.password);
  if (!passwordOk) { return res.status(401).send("Invalid username/password"); }

  const payload = { username: user.username };
  const options = { expiresIn: "5m" };
  const token = jwt.sign(payload, process.env.SECRET, options);
  res.send(token);
});

// This endpoint is secured; only requests with a valid token can access ot
app.get("/secure", checkTokenMiddleware, (req, res) => {
  res.send(`Hooray, ${req.user.username}, you have access!`);
});

app.listen(process.env.PORT, () => {
  console.log("Listening on http://localhost:" + process.env.PORT);
});
