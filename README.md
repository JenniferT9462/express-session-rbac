# express-session-rbac
## Overview
This project focuses on setting up a secure Express application that incorporates key authentication and authorization functionalities with an emphasis on Role-Based Access Control (RBAC).
## Setup
### Project setup:
- In your terminal make sure you `cd` into the directory that you want your project to go.
    - Make a new directory for your project:
        ```bash
        mkdir express-session-rbac
    - Go into that directory:
        ```bash
        cd express-session-rbac
    - Initialize `Node.js`:
        ```bash
        npm init -y
    - Install dependencies for the project:
        ```bash
        npm install express mongoose dotenv jsonwebtoken bcryptjs
    - Open your new project in VSCode:
        ```bash
        code .
### Create the Server:
- Create a file named `index.js`.
    - Copy this server code into `index.js`:
        ```js
        // index.js
        const express = require('express');
        const mongoose = require('mongoose');
        const app = express();
        const port = 3000;

        // Middleware to parse JSON bodies
        app.use(express.json());

        // Connect to MongoDB
        mongoose
        .connect('your-mongodb-connection-string-here', {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        })
        .then(() => {
            console.log('Connected to MongoDB');
        })
        .catch((error) => {
            console.error('Error connecting to MongoDB:', error);
        });

        app.get('/', (req, res) => {
            res.send('Hello, World!');
        });

        app.listen(port, () => {
            console.log(`Server is running at http://localhost:${port}`);
        });


- In order to keep our `connection string` secure, we will need to store it in a `.env` file. 
    - Create a file named `.env`.
    - Define a variable for your `connection string`. NOTE: Your variable should be in all caps and no spaces between the variable and `=` or after.
        Example: `ATLAS_URL=mongodb+srv://<username>:<password>@cluster0.x3zgp.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`
    - In order for us to use the environment variable in our server, we will need to import an configure dotenv:
        ```js
        require('dotenv').config()
    - We can add a console.log to confirm it is working, but remove after confirming:
        ```js
        console.log(process.env)
    - To use the environment variable in the server code, you can store it in a new variable to use it where you originally put your `connection string`:
        ```js
        const atlasUrl = process.env.ATLAS_URL
    - Replace your `'your-mongodb-connection-string-here'` with the new variable. 
- Test the Connection:
    - Start the server by running `node index.js`
    - In the terminal it should log `Connected to MongoDB`.
    - Navigate to `localhost/3000` in your browser to confirm that the page displays `Hello World!`. 

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

### Authentication
- Access Protected Route:
    * Method: GET
    * Endpoint: http://localhost:3000/dashboard
    * Header: Authorization: Bearer <your_jwt_token>
    * Response:
        ```json
        {
        "message": "This is the dashboard."
        }
    * Screenshot:
    ![dashboard](</img/dashboardPostman.png>)
### Role-Based Access Control
- Register an Admin User:
    * Method: POST
    * Endpoint: http://localhost:3000/register
    * Response: 
        ```json
        {
            "name": "Admin User",
            "email": "AnnaRose@gmail.com",
            "password": "$2a$10$KL6Ro8/.MX7oSRskswfcjODd8uPluGZgGkB5jVXtZQyoIp7KEJ3gK",
            "role": "admin",
            "_id": "675dd467671344efbf206270",
            "__v": 0
        }
    * Screenshot:
    ![admin register](</img/adminPostman.png>)
- Register a Regular User:
    * Method: POST
    * Endpoint: http://localhost:3000/register
    * Response:
        ```json
        {
            "name": "Regular User",
            "email": "user@example.com",
            "password": "$2a$10$4n3WYMceqQZ6FsyyWTopROuxx.m.Ax.BYfDyqCPGtx1P.J8oe0",
            "role": "user",
            "_id": "675ccd549708fcef93f3681c",
            "__v": "0",
        }
    * Screenshot:
    ![reg user](</img/regUserPostman.png>)
- Login as Admin User:
    * Method: POST
    * Endpoint:  http://localhost:3000/login
    * Response:
        ```json
        {
            "message": "Login successful",
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY3NWRkNDY3NjcxMzQ0ZWZiZjIwNjI3MCIsImVtYWlsIjoiQW5uYVJvc2VAZ21haWwuY29tIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzM0MjAyNTQ5LCJleHAiOjE3MzQ4MDczNDl9.ZWOy6Y_gs2jIRY31OVWHqNO-hlAUtzfjhWSLxJCFzE4"
        }
    * Screenshot:
    ![admin login](</img/adminLoginPostman.png>)
- Access Admin Route as Admin User:
    * Method: GET
    * Endpoint: http://localhost:3000/admin
    * Header: Authorization: Bearer <your_jwt_token>
    * Response:
        ```json
        {
            "message": "This is the admin panel."
        }
    * Screenshot:
    ![access admin as admin user](</img/accessAdminAdminPostman.png>)
- Access Admin Route as Regular User:
    * Method: GET
    * Endpoint: http://localhost:3000/admin
    * Header: Authorization: Bearer <your_jwt_token>
    * Response: 
        ```json
        {
            "message": "Access Forbidden: Insufficient permissions."
        }
    * Screenshot:
    ![admin route as reg user](</img/adminRegUserPostman.png>)

## Initialize a Git Repository
- In your bash terminal, add a `.gitignore`:
    ```bash
    touch .gitignore
- Include `node_modules` and `.env`:
    ```bash
    echo "node_modules/" >> .gitignore
    echo ".env" >> .gitignore
- Create a new repository on Github, without a README.md or .gitignore.
- Back in bash initialize a empty repo:
    ```bash
    git init
- Add files to be staged for commit:
    ```bash
    git add .
- Initial commit:
    ```bash
    git commit -m "initial commit"
- Add a main branch:
    ```bash
    git branch -M main
- Add your new repository:
    ```bash
    git remote add origin https://github.com/username/reponame.git
- Push to Github
    ```bash
    git push -u origin main
## Challenges
Figuring out the `secret key` in the JWT sign method was challenging because I didn't know that the secret key can be anything as long as it is very secure and strong. 

I didn't include `auth` middleware in my admin route and that is why it wasn't working. My error said that couldn't read "user.role" from my role middleware. That was because I didn't included the auth before my role middleware. So it didn't have the role info on my admin route. And didn't have that data to compare with. So it crashed. When I added `auth` in the `admin` route it worked again.

## Conclusion
This project equips developers with essential skills to build scalable and secure web applications using Express, with a focus on enhancing user management and resource protection through RBAC.
## Acknowledgements
- MongoDB Password Auth - <https://www.mongodb.com/blog/post/password-authentication-with-mongoose-part-1>
- Stack Overflow - <https://stackoverflow.com/questions/31309759/what-is-secret-key-for-jwt-based-authentication-and-how-to-generate-it>
- NPM jsonwebtoken - <https://www.npmjs.com/package/jsonwebtoken>
- GeeksforGeeks JWT - <https://www.geeksforgeeks.org/json-web-token-jwt/>
- GeeksforGeeks JWT Implementation - <https://www.geeksforgeeks.org/how-to-implement-jwt-authentication-in-express-js-app/>
- Generate a secret key with Node.js - <https://dev.to/tkirwa/generate-a-random-jwt-secret-key-39j4>



