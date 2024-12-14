const express = require("express");
const mongoose = require("mongoose");
const app = express();
const port = 3000;

//Import environment variables
require("dotenv").config();
const atlasUrl = process.env.ATLAS_URL;

//Import jwt
const jwt = require("jsonwebtoken");

//Use jwt secret key
const secretKey = process.env.JWT_SECRET;
const secretKeyExpires = process.env.JWT_EXPIRES_IN;

//Import user model
const User = require("./models/User");

//Import auth middleware
const auth = require('./middleware/auth');
//Import role middleware
const checkRole = require('./middleware/role')

//Middleware to parse JSON
app.use(express.json());

mongoose
  .connect(atlasUrl, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((error) => {
    console.error("Error connecting to MongoDB:", error);
  });

app.get("/", (req, res) => {
  res.send("Hello, World!");
});

//Register route
app.post("/register", async (req, res) => {
  // Extract the request body containing the user data
  const data = req.body;
  // Create a new User instance with the provided data
  const user = new User({
    name: data.name,
    email: data.email,
    password: data.password,
    role: data.role
  });

  try {
    // Save the user data to the database
    const savedUser = await user.save();
    console.log(savedUser);
    // Send the saved user data as a JSON response
    res.json(savedUser);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to save user" });
  }
});

//Login Route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    //Find the user by email
    const user = await User.findOne({ email });
    //If not user send error
    if (!user) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    //Compare provided password with the hashed password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    //Generate jwt token
    const token = jwt.sign({ id: user._id, email: user.email, role: user.role }, secretKey, {
      expiresIn: secretKeyExpires,
    });
    //Return token in response
    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
      console.error(error);
      res.status(500).json({ error: "Server error" });
  }
});

//Access protected resource
app.get('/dashboard', auth, (req, res) => {
  res.json({
    message: "This is the dashboard."
  })
})

//Admin-only protected route
app.get('/admin', auth, checkRole("admin"), (req, res) => {
  res.status(200).json({ message: "This is the admin panel."})
})

//Start the server
app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
