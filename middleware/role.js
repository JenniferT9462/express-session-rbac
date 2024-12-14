const checkRole = (role)  => {
    return (req, res, next) => {
        const userRole = req.user.role;
        console.log(userRole);
        if (userRole === role) {
            return next();
        } else {
            return res.status(403).json({ message: "Access Forbidden: Insufficient permissions." })
        }
    }
}

module.exports = checkRole;