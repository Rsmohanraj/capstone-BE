const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt =require('jsonwebtoken');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Please enter your name'],
        minlength: 2,
        maxLength: 50
    },
    email: {
        type: String,
        required: [true, 'Please enter your email'],
        unique: true,
        
        
    },
    password: {
        type: String,
        required: [true, 'Please enter a password'],
      
        
    },
    avatar:{
        type: String,
       
    },
    role:{
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },
    createAt:{
        type: Date,
        default: Date.now
    },


});

let model =mongoose.model('User', userSchema);

module.exports = model;