//Import jwt
const jwt = require("jsonwebtoken");

//Use jwt secret key
const secretKey = process.env.JWT_SECRET;


const auth = ((req, res, next) => {
    try {
        //The auth header
        const bearerToken = req.headers.authorization;
        //Authorization 'Bearer TOKEN' - must have token
        if (!bearerToken) {
            res.status(401).json({
                success: false,
                message: "Error! Token was not provided."
            })
        }
        //Split the 'Bearer' from the bearerToken
        const token = bearerToken.split(' ')[1];
        if (!token) {
            return res.status(401).json({
                success: false,
                message: "Error! Token was not provided."
            });
        }
        //Decode and verify the token 
        console.log('Token received:', token);
        //Decoding the token
        const decodedToken = jwt.verify(token, secretKey);
        console.log('Decoded Token:', decodedToken);
    
        req.user = {
            userId: decodedToken.name,
            email: decodedToken.email,
            role: decodedToken.role
        }
        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: "Error! Unauthorized access.",
            error: error.message
        })
    }
})

module.exports = auth;