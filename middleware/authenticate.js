const ErrorHandler = require('../Utils/errorHandler');
const User = require('../models/userModel')
const catchAsyncError = require("./catchAsyncError");
const jwt = require('jsonwebtoken');
exports.isAuthenticatedUser =  catchAsyncError(async (req, res, next) => {

    const token =req.header("Authorization")?.split(" ")[1];
    if(!token) {
        return res.status(401).json({message: "You are not authenticated"});
    }
    try {
        const verified =jwt.verify(token,process.env.JWT_SECRET);
        req.userId = verified.userId;
        next();
    } catch (error) {
        res.status(400).json({message: "invalid Token"})
        
    }
})

exports.isAuthenticateRole  =  (roles) => {
    return async (req, res, next) => {
        try {
            const user =await User.findById(req.userId);
            if(!user || !roles.includes(user.role)){
                return res.status(403).json({message:"Access denied"})
            }
            next();
        } catch (error) {
            res.status(500).json({message:"Server Error"})
            
        }
    }
}


    