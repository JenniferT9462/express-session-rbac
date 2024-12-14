# express-session-rbac
## Overview
This project focuses on setting up a secure Express application that incorporates key authentication and authorization functionalities with an emphasis on Role-Based Access Control (RBAC).
## Setup


## User Schema and Password Hashing
- Define a user schema with the following fields: `name`, `email`, `password`, and `role`.
    * Create a directory named `models`.
    * Inside `models` create a file named `User.js`.
    * Import the necessary libraries:
        ```js
        const mongoose = require('mongoose');
        const bcrypt = require("bcryptjs"); 
    * Define the Schema:
        ```js
        //Define the user schema
        const userSchema = mongoose.Schema({
            name: { type: String, required: true },
            email: { type: String, required: true, unique: true },
            password: { type: String, required: true },
            //'enum' stands for enumeration. Restricts values to predefined roles like user and admin.
            role: { type: String, enum: ['user', 'admin'], default: 'user' }
        });
- Implement password hashing using `bcrypt` before saving the user.
    * This involves securely converting the user's plain-text password into a hashed format.
    * `bcrypt`: is a library designed for hashing passwords securely. It makes brute-force attacks(trying every possible password) more time-consuming.
    * `Salt`: Bcrypt automatically generates a salt (random data added to the password) and incorporates it into the hash. This makes each hash unique, even if two users have the same password.
    * `Hashing Workflow`:
        - The plain-text password is combined with a salt.
        - The bcrypt algorithm generates a hash based on the password and salt.
        - Only the hash(not the original password) is stored in the database.
    * Add the Password Hashing under the User Schema:
        ```js
        //Hash bcrypt
        userSchema.pre('save', async function (next) {
            const salt = await bcrypt.genSalt(10);
            const plainTextPassword = this.password;
            const encryptedPassword = await bcrypt.hash(plainTextPassword, salt);
            this.password = encryptedPassword;
            next();
        })
- Create the Model:
    ```js
    //Create the User model
    const User = mongoose.model('User', userSchema);
- Export the User module:
    ```js
    //Export the model
    module.exports = User;

## Routes
### Register
- Route to register a new user with hashed passwords `POST /register`.
- Make a `POST` route based on the user schema from `User.js`.
    ```js
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
- When a user registers the password will be hashed using `bcrypt` before saving the user. This happens in the `User.js` file. 
### Login
- Route to login a user and return a JWT token `POST /login`.
- Make sure you have JWT installed:
    ```bash
    npm install jsonwebtoken
- A `JWT (JSON Web Token)` is a secure way to share information between two parties, like a user and a website or app. It's a small package of data that includes information about a user or session, and it's digitally signed to ensure that it hasn't been tampered with.
- JWT is made up of three parts:
    ```css
    HEADER.PAYLOAD.SIGNATURE
- Example of a JWT token:
    ```bash
    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
    .
    eyJ1c2VySWQiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0
    .
    SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
- The `header` is made up of `metadata` about the token.
    ```json
    { "alg": "HS256", "typ": "JWT" }
- The `payload` contains the actual data being sent. Example:
    ```json
      { "userId": "1234567890", "email": "admin@example.com",  "role": "admin" }
- The `signature` makes sure the token hasn't been tampered with. The `secret key`. It's generated on your end. 
- You can verify you JWT token at <https://jwt.io> for debugging purposes. 
- Use Node.js to generate a secret key:
    ```bash
    node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

- The secret key will be logged in the terminal, copy and paste that into a `.env` file. 
- Create or update your `index.js` file to include the necessary imports:
    ```js
    const express = require("express");
    const mongoose = require("mongoose");
    const bcrypt = require("bcryptjs");
    const jwt = require("jsonwebtoken");

    // Import your User model
    const User = require("./models/User");

    const app = express();
    // Parses incoming JSON requests
    app.use(express.json()); 

    //Use jwt secret key
    const secretKey = process.env.JWT_SECRET;
    const secretKeyExpires = process.env.JWT_EXPIRES_IN;
- Add a method to compare passwords in the `User.js` file:
    ```js
    //Method to compare passwords
    userSchema.methods.comparePassword = function (inputPassword) {
        return bcrypt.compare(inputPassword, this.password);
    }
- Define the `/login` route.
    ```js
    //Login Route
    app.post("/login", async (req, res) => {
        // Extract email and password from request body
        const { email, password } = req.body;

        try {
            // Step 1: Find the user by email
            const user = await User.findOne({ email });
            //If not user send error
            if (!user) {
                return res.status(401).json({ error: "Invalid email or password" });
            }

            // Step 2: Compare provided password with the hashed password
            const isMatch = await user.comparePassword(password);
            if (!isMatch) {
                return res.status(401).json({ error: "Invalid email or password" });
            }

            // Step 3: Generate a JWT token
            const token = jwt.sign(
                { id: user._id, email: user.email, role: user.role },
                // Secret key for signing 
                secretKey, 
                // Token expiration
                { expiresIn: secretKeyExpires }
            );
            // Step 4: Send response with the token
            res.status(200).json({ message: "Login successful", token });
        } catch (error) {
            // Log the error for debugging
            console.error(error);
            // Return a server error
            res.status(500).json({ error: "Server error" });
        }
    });

## Middleware
### Authentication
- Create a directory named `middleware`.
- Create a file named `auth.js`. 
- Start by importing the jsonwebtoken library, which is used to decode and verify JSON Web Tokens (JWT):
    ```js
    const jwt = require("jsonwebtoken");
- Define the `Secret Key`:
    * Use the `process.env.JWT_SECRET` environment variable to store your secret key securely.
    * The `secret key` is used to verify the authenticity of the JWT:
    ```js
    const secretKey = process.env.JWT_SECRET;
- Create the `auth` Middleware Function:
    * This function acts as middleware in an Express.js app to handle authentication via JWT.
    ```js
    const auth = ((req, res, next) => {

    });
- Extract the `Authorization Header`:
    * Retrieve the authorization header from the incoming request object `req.headers.authorization`.
    * This header should contain the token in the format: "Bearer TOKEN".
    ```js
    const bearerToken = req.headers.authorization;
- Verify whether the authorization header is present. If not, respond with a `401 Unauthorized` error: 
    ```js
    if (!bearerToken) {
        res.status(401).json({
            success: false,
            message: "Error! Token was not provided."
        });
    }
- Extract the Token:
    * Split the bearerToken string using the space (' ') as a delimiter to separate "Bearer" from the actual token.
    * Check if the token exists. If it's missing, send another `401 Unauthorized` response:
    ```js
    const token = bearerToken.split(' ')[1];
    if (!token) {
        return res.status(401).json({
            success: false,
            message: "Error! Token was not provided."
        });
    }
- Verify the Token:
    * Use `jwt.verify` to decode and verify the token with the secretKey.
    * If the token is invalid or verification fails, an error will be thrown:
    ```js
    const decodedToken = jwt.verify(token, secretKey);
- Log the Token and Decoded Information:
    * Print the received token and decoded token for debugging purposes:
    ```js
    console.log('Token received:', token);
    console.log('Decoded Token:', decodedToken);
- Attach Decoded Information to the req Object:
    * Extract specific properties from the decoded token (e.g., userId, email, role) and attach them to req.user.
    * This makes user information accessible in downstream middleware or route handlers:
    ```js
    req.user = {
        userId: decodedToken.name,
        email: decodedToken.email,
        role: decodedToken.role
    };
- Call `next()` to pass control.
- Export the Middleware:
    ```js
    module.exports = auth;
- Use the `auth` middleware in your Express routes:
    ```js
    //Import auth middleware
    const auth = require('./middleware/auth');
    //Access protected resource
    app.get('/dashboard', auth, (req, res) => {
        res.json({
            message: "This is the dashboard."
        })
    })
### Role-Based Access Control (RBAC)
- Create a new file in `middleware` directory named `role.js`.
- Define a function that accepts a `role`:
    ```js 
    const checkRole = (role) => {}
- The `checkRole` function is a middleware for role-based access control in a Node.js application. It ensures that only users with a specific role can access certain routes.
- Return a middleware function:
    ```js
    return (req, res, next) => {}
- Access the user's role:
    ```js
    const userRole = req.user.role;
- Log the User's Role:
    ```js
    console.log(userRole);
- The user's role is logged to the console, which can help with debugging by confirming what role is being checked.
- Check If the User's Role Matches the Required Role:
    ```js
    if (userRole === role) {
            return next();
        } else {
            return res.status(403).json({ message: "Access Forbidden: Insufficient permissions." })
        }
- Export the middleware:
    ```js
    module.exports = checkRole;
- In your routes, you would use the `checkRole` middleware like this:
    ```js
    //Admin-only protected route
    app.get('/admin', auth, checkRole("admin"), (req, res) => {
        res.status(200).json({ message: "This is the admin panel."})
    })
- Make sure you include `auth` middleware in the route before `checkRole("admin")`. 
## Testing
### Register and Login
- Register a User:
    * Method: POST
    * Endpoint: http://localhost:3000/register
    * Response:
        ```json
        {
            "name": "Penelope",
            "email": "NellieDog@gmail.com",
            "password": "$2a$10$PnqqFyaYfL/CkK/uNbluBuz1iRfEZrVf1UY5ZMbLKdZeuP8MUe1VK",
            "_id": "675c4db557491553eb21c9d0",
            "__v": 0
        }
    * Screenshot:
    ![register user](</img/registerUserPostman.png>)
- Login a User:
    * Method: POST
    * Endpoint: http://localhost:3000/login
    * Response:
        ```json
        {
            "message": "Login successful",
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY3NWM0ZGI1NTc0OTE1NTNlYjIxYzlkMCIsImVtYWlsIjoiTmVsbGllRG9nQGdtYWlsLmNvbSIsImlhdCI6MTczNDEwMjU0MiwiZXhwIjoxNzM0MTAyNTQyfQ.BXocVGZa5leAm_Es7h9MAk1adMl_5icO7gWMS7fwDn0"
        }
    * Screenshot:
    ![login a user](</img/loginUserPostman.png>)

### Role-Based Access Control


## Initialize a Git Repository
## Challenges
I didn't include 'auth' middleware in my admin route and that is why it wasn't working. My error said that couldn't read "user.role" from my role middleware. That was because I didn't included the auth before my role middleware. So it didn't have the role info on my admin route. And didn't have that data to compare with. So it crashed
## Conclusion
This project equips developers with essential skills to build scalable and secure web applications using Express, with a focus on enhancing user management and resource protection through RBAC.
## Acknowledgements
- MongoDB Password Auth - <https://www.mongodb.com/blog/post/password-authentication-with-mongoose-part-1>
- Stack Overflow - <https://stackoverflow.com/questions/31309759/what-is-secret-key-for-jwt-based-authentication-and-how-to-generate-it>
- NPM jsonwebtoken - <https://www.npmjs.com/package/jsonwebtoken>
- GeeksforGeeks JWT - <https://www.geeksforgeeks.org/json-web-token-jwt/>
- GeeksforGeeks JWT Implementation - <https://www.geeksforgeeks.org/how-to-implement-jwt-authentication-in-express-js-app/>
- Generate a secret key with Node.js - <https://dev.to/tkirwa/generate-a-random-jwt-secret-key-39j4>



