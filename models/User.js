const mongoose = require('mongoose');
const bcrypt = require("bcryptjs");

//Define the user schema
const userSchema = mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    //'enum' stands for enumeration. Restricts values to predefined roles like user and admin.
    role: { type: String, enum: ['user', 'admin'], default: 'user' }
});

//Hash bcrypt
userSchema.pre('save', async function (next) {
    const salt = await bcrypt.genSalt(10);
    const plainTextPassword = this.password;
    const encryptedPassword = await bcrypt.hash(plainTextPassword, salt);
    this.password = encryptedPassword;
    next();
})

//Method to compare passwords
userSchema.methods.comparePassword = function (inputPassword) {
    return bcrypt.compare(inputPassword, this.password);
}

//Create the User model
const User = mongoose.model('User', userSchema);

//Export the model
module.exports = User;
