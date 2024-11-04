const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const app = express();
const User = require("./models/User");
const Post = require("./models/Post");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const uploadMiddleware = multer({ dest: "uploads/" });
const fs = require("fs");
require("dotenv").config();


const SECRET_KEY = process.env.SECRET_KEY; // Change this to a secure, unique key

app.use(
  cors({
    origin: process.env.CORS_ORIGIN, // Set your frontend origin
    credentials: true, // Enable credentials (cookies) for cross-origin requests
  })
);
app.use(express.json());
app.use(cookieParser());
app.use("/uploads", express.static(__dirname + "/uploads"));

mongoose.connect(process.env.MONGODB_URI);

app.post("/register", async (req, resp) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const userDoc = await User.create({
      username,
      password: hashedPassword,
    });

    const token = jwt.sign(
      { id: userDoc._id, username: userDoc.username },
      SECRET_KEY,
      {
        expiresIn: "1h",
      }
    );

    // Set the token as a cookie
    resp.cookie("token", token, {
      httpOnly: true, // Prevents JavaScript access to the cookie
      secure: false, // Use secure cookies (set to true if using HTTPS)
      maxAge: 60 * 60 * 1000, // Cookie expiration (1 hour)
      sameSite: "Strict", // Restrict cross-site cookie sharing
    });

    resp.status(201).json({ user: userDoc });
  } catch (error) {
    if (error.code === 11000) {
      resp.status(400).json({ error: "Username already exists." });
    } else if (error.name === "ValidationError") {
      resp
        .status(400)
        .json({ error: "Validation failed", details: error.message });
    } else {
      resp
        .status(500)
        .json({ error: "An error occurred during registration." });
    }
  }
});

app.post("/login", async (req, resp) => {
  try {
    const { username, password } = req.body;

    const userDoc = await User.findOne({ username });

    if (!userDoc) {
      return resp.status(400).json({ error: "Invalid username or password." });
    }

    const isMatch = await bcrypt.compare(password, userDoc.password);

    if (!isMatch) {
      return resp.status(400).json({ error: "Invalid username or password." });
    }

    const token = jwt.sign(
      { id: userDoc._id, username: userDoc.username },
      SECRET_KEY,
      {
        expiresIn: "1h",
      }
    );

    // Set the token as a cookie
    resp.cookie("token", token, {
      httpOnly: true,
      secure: false,
      maxAge: 60 * 60 * 1000,
      sameSite: "Lax",
    });

    resp.status(200).json({
      message: "Login successful!",
      user: {
        id: userDoc._id,
        username: userDoc.username,
      },
    });
  } catch (error) {
    resp.status(500).json({ error: "An error occurred during login." });
  }
});

app.get("/profile", (req, res) => {
  const { token } = req.cookies;
  jwt.verify(token, SECRET_KEY, {}, (err, info) => {
    if (err) throw err;
    res.json(info);
  });
});
app.post("/logout", (req, res) => {
  res
    .cookie("token", "", {
      httpOnly: true, // Important for security
      secure: false, // Set to true if using HTTPS
      maxAge: 0, // Expire the cookie immediately
      sameSite: "Strict", // Adjust according to your needs
    })
    .json({ message: "Logged out successfully" });
});

app.post("/post", uploadMiddleware.single("file"), async (req, res) => {
  const { originalname, path } = req.file;
  const parts = originalname.split(".");
  const ext = parts[parts.length - 1];
  const newPath = path + "." + ext;
  fs.renameSync(path, newPath);
  const { token } = req.cookies;
  jwt.verify(token, SECRET_KEY, {}, async (err, info) => {
    if (err) throw err;
    const { title, summary, content } = req.body;
    const postDoc = await Post.create({
      title,
      summary,
      content,
      cover: newPath,
      author: info.id,
    });

    res.json(postDoc);
  });
});

app.get("/post", async (req, res) => {
  const posts = await Post.find()
    .populate("author", ["username"])
    .sort({ createdAt: -1 })
    .limit(20);
  res.json(posts);
});

app.get("/post/:id", async (req, res) => {
  const { id } = req.params;
  const postDoc = await Post.findById(id).populate("author", ["username"]);
  res.json(postDoc);
});

app.put("/post/:id", uploadMiddleware.single("file"), async (req, res) => {
  let newPath = null;
  if (req.file) {
    const { originalname, path } = req.file;
    const parts = originalname.split(".");
    const ext = parts[parts.length - 1];
    newPath = path + "." + ext;
    fs.renameSync(path, newPath);
  }

  const { token } = req.cookies;

  jwt.verify(token, SECRET_KEY, {}, async (err, info) => {
    if (err) {
      return res.status(401).json("Token verification failed");
    }

    try {
      const { id, title, summary, content } = req.body;
      const postDoc = await Post.findById(id);

      if (!postDoc) {
        return res.status(404).json("Post not found");
      }

      const isAuthor =
        JSON.stringify(postDoc.author) === JSON.stringify(info.id);
      console.log(postDoc.author, info.id);
      if (!isAuthor) {
        return res.status(403).json("You are not the author");
      }

      // Update fields and save
      postDoc.set({
        title,
        summary,
        content,
        cover: newPath ? newPath : postDoc.cover,
      });
      await postDoc.save();

      res.json(postDoc);
    } catch (error) {
      console.error(error);
      res.status(500).json("Internal server error");
    }
  });
});

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => console.log("Server running on port 4000"));
