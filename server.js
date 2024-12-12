const app =require('./app');
require('dotenv').config();
const mongoose = require('mongoose');
const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const bodyParser = require('body-parser');
dotenv.config();






app.use(bodyParser.json())
app.use(cors({
    origin: 'https://guvi-ecomm.netlify.app/', // replace with your frontend URL
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'] ,
    allowedHeaders: ['Content-Type', 'Authorization'], // replace with your allowed HTTP methods
}));

const PORT =process.env.PORT || 8000;
mongoose.connect(process.env.DB_LOCAL_URI)
.then(() =>{
    console.log("Connected to MongoDB Successfully");
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
})
.catch((error) =>{
    console.error("Error connecting to MongoDB", error);
})