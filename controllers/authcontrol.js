const catchAsyncError= require('../middleware/catchAsyncError');
const User= require('../models/userModel');
const nodemailer = require('nodemailer');
const ErrorHandler= require('../Utils/errorHandler');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');


exports.registerUser = catchAsyncError(async(req, res, next) => {
  try {
    const {name,email,password} = req.body;
    const hashPassword =await bcrypt.hash(password,10);
    const user =new User({name,email,password: hashPassword});
    await user.save();
    res.status(201).json({ message: "User registered successfully" ,
      
      token: jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' }) // Generate a JWT token
    });
   
  } catch (error) {
    res.status({message: error.message})
    
  }
})
//login user//
exports.loginUser = catchAsyncError(async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if email exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // Check if the provided password matches the stored hashed password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // Create JWT token
    const token = jwt.sign(
      { userId: user._id }, // Payload
      process.env.JWT_SECRET, // Secret key (should be stored in .env file)
      { expiresIn: '1h' }    // Expiration time (expires in 1 hour)
    );

    // Send the token to the client
    res.status(200).json({ token });
    
  } catch (error) {
    // Error handling
    console.error("Error:", error);
    res.status(500).json({ message: error.message });
  }
});
//logout user//
exports.logoutUser =(req, res, next) => {
  res.cookie('ticket', null, { expires: new Date(Date.now()),
      httpOnly: true
   })
   .status(200).json({
    success: true,
    message: 'Logged out successfully'
   })
  

  }
  //forget password//
  exports.forgetPassword = catchAsyncError(async (req, res, next) => {
    const { email } = req.body;
  
    try {
      // Find the user with the given email
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      // Generate a reset token
      const token = crypto.randomBytes(20).toString('hex');
      user.resetPasswordToken = token;
      user.resetPasswordExpires = Date.now() + 10 * 60 * 1000; // 10 minutes from now
  
      // Save the user with the reset token and expiry
      await user.save();
  
      // Setup the email transport using Gmail (or configure your own email provider)
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER,  // Your email here
          pass: process.env.EMAIL_PASS   // Your email password or app password here
        },
        tls: { rejectUnauthorized: false },  // Disable SSL certificate verification if needed
      });
  
      // Setup the email options
      const mailOptions = {
        from: process.env.EMAIL_USER,   // Sender address
        to: user.email,                // Receiver address
        subject: 'Password Reset Request',  // Subject
        text: `You are receiving this email because you (or someone else) has requested a password reset for your account.\n\nClick on the following link to reset your password: https://e-commercemyapp.netlify.app/password/reset/${token}`  // Reset link
      };
  
      // Send the email with the reset link
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Error sending email:', error);
          return res.status(500).json({ message: 'Failed to send password reset email' });
        } else {
          console.log('Email sent:', info.response);
          return res.status(200).json({ message: 'Password reset email sent successfully' });
        }
      });
    } catch (error) {
      console.error('Error in forgetPassword:', error);
      return res.status(500).json({ message: 'Failed to send password reset email' });
    }
  });

  //resetPassword//
  exports.resetPassword = catchAsyncError(async (req, res, next) => {
    const { token } = req.params;  // Get token from the URL parameter
    const { password } = req.body;  // Get new password from the request body
  
    try {
      // Find the user with the matching reset token and check if the token hasn't expired
      const user = await User.findOne({
        
        resetPasswordToken: token,
        resetPasswordExpires: { $gt: Date.now() }  // Token expiry check
      });
  
      // If the user is not found or the token has expired, return an error message
      if (!user) {
        return res.status(404).json({ message: 'Invalid or expired token' });
      }
  
      // Hash the new password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Set the new password, and clear the reset token and expiry
      user.password = hashedPassword;
      user.resetPasswordToken = null;  // Clear the reset token after use
      user.resetPasswordExpires = null;  // Clear the reset token expiry after use
  
      // Save the updated user information
      await user.save();
  
      // Send a success response
      res.status(200).json({ message: 'Password reset successfully' });
    } catch (error) {
      console.error('Error during password reset:', error);
      // Return a generic error response (for security reasons, avoid exposing error details to users)
      res.status(500).json({ status: false, message: 'Failed to reset password, please try again later' });
    }
  });
  //get user profile//
exports.UserProfile = catchAsyncError(async (req, res) => {
  try {
    
    const user = await User.findById(req.userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json({
      success: true,
      user
    });
    
  } catch (error) {
    // Send a bad request response with error message
    res.status(400).json({ message: 'Bad Request: ' + error.message });
  }
});

 
  //update user profile//
  exports.updateProfile = catchAsyncError(async (req, res,next) => {
    const newUserData = {
      name: req.body.name,
      email: req.body.email,
      
    }
    const user = await User.findByIdAndUpdate(req.userId, newUserData,{
      new: true,
      runValidators: true
    });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json({
      success: true,
      user
    });
  });
  //Admin: get all users//
  exports.getAllUsers = catchAsyncError(async (req, res) => {
    try {
      const user =await User.find();
      res.json({user});
    } catch (error) {
      res.json({error: error.message});
    }
  })
    
  //Admin Specific user//
  exports.getUser = catchAsyncError(async (req, res, next) => {
    const user = await User.findById(req.params.id);
    if(!user){
      return next(new ErrorHandler(`No user found with that id ${req.params.id}`));
    }
    res.status(200).json({
      success: true,
      user
    })

  })


  //Admin update user//
  exports.updateUser = catchAsyncError(async (req, res, next) => {
    const newUserData ={
      name: req.body.name,
      email: req.body.email,
      role: req.body.role 
      
    }
      const user = await User.findByIdAndUpdate (req.params.id, newUserData,{
      new: true,
      runValidators: true
    })
       
    res.status(200).json({
      success: true,
      user
    })


   
  })

  //Admin delete user//
  exports.deleteUser = catchAsyncError(async (req, res, next) => {
    const user = await User.findById(req.params.id);
    if(!user){
      return next(new ErrorHandler(`No user found with that id ${req.params.id}`));
    }
    await user.deleteOne();
    res.status(200).json({
      success: true,
      message: 'User deleted successfully'
    })
    
    })
    
    
