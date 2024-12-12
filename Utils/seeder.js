const products = require('../Data/Product.json');
const product = require ('../models/ProductModel');
const dotenv = require('dotenv');
;

const connectDatabase = require('../config/database');
dotenv.config({path:"backend/config/config.env"});
connectDatabase();

const seedProducts = async () => {
    try {
        await product.deleteMany();
        console.log(' all Products deleted successfully');
        await product.insertMany(products);
        console.log(' all Products seeded successfully');
    } catch (error) {
        console.log('Error seeding products', error);
    }


}

seedProducts();