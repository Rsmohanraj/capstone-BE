const mongoose = require('mongoose');
const ProductSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true,"please enter product name"],
        trim :true,
        maxLength : [100,"product name cannot be more than 100 characters"]
    },
    price: {
        type: Number,
        required: true,
        default:0.0
    },
    description: {
        type: String,
        required: [true,"please enter a description"]
    },
    ratings: {
        type: String,
        default: 0
    },
    images: [
        {
        image:{
                type: String,
                required: true
            }
        }
    ],
    category: {
        type: String,
        required: [true,' Select category '],
        enum: {
            values: [
                'Electronics',
                'Accessories',
                'Fashion',
                'Headphones',
                'Home',
                'Sports',
                'Toys',
                'Laptops',
                'Mobile Phones',
                'Others'
                
            ]
           
        }
    },
    seller:{
        type: String,
        required: [true,"please enter seller name"],
       
    },
    stock: { type: Number, required: true },
   
    numOfReviews: {
        type: Number,
        default: 0
    },
    reviews: [
        {
            user: {
                type:mongoose.Schema.Types.ObjectId,
            ref:'User'
            },
            name: {
                type: String,
                required: true
            },
            
            rating: {
                type: String,
                required: true
            },
            comment: {
                type: String,
                required: true
            }
        }
    ],
    user:{
        type: mongoose.Schema.Types.ObjectId,
        
    },
    createdAt: {
        type: Date,
        default: Date.now()
    }
});
 let Schema = mongoose.model('Product',ProductSchema)

 module.exports = Schema;