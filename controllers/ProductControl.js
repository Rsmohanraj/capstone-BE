const Product = require('../models/ProductModel');
const ErrorHandler = require('../Utils/errorHandler')
const catchAsyncError = require('../middleware/catchAsyncError');
const APIFeatures = require('../Utils/apiFeature');

const multer =require ('multer')
const dotenv = require('dotenv');

dotenv.config();






//Get Products - /api/v1/products
exports.getProducts = catchAsyncError(async (req, res, next)=>{
   const resPerPage =3;
   let buildQuery =() => {
    return new APIFeatures(Product.find(),req.query).search().filter()
   }

  const filteredProductsCount =await buildQuery().query.countDocuments({})
   const totalProductsCount = await Product.countDocuments({})
   let productsCount =totalProductsCount;

   if(filteredProductsCount !== totalProductsCount) {
     productsCount = filteredProductsCount;
   }
   const products = await buildQuery().paginate(resPerPage).query;
   res.status(200).json({
       success: true,
       count: productsCount,
       resPerPage,
       products
   })
})

//Create Product - /api/v1/product/new
exports.newProduct = catchAsyncError(async (req, res, next)=>{
    
    let images=[]
    if(req.files.length > 0){
        req.files.forEach(file => {
            let url = `${process.env.BACKEND_URL}/uploads/product/${file.originalname}`
            images.push({image:url})
        })
    }
    req.body.images = images;

    const product = await Product.create(req.body);
    res.status(201).json({
        success: true,
        product,
       
    })
});

//Get Single Product - api/v1/product/:id
exports.getSingleProduct = catchAsyncError(async(req, res, next) => {
    const product = await Product.findById(req.params.id).populate('reviews.user','name email');

    if(!product) {
        return next(new ErrorHandler('Product not found', 400));
    }

    res.status(201).json({
        success: true,
        product
    })
})

//Update Product - api/v1/product/:id
exports.updateProduct = catchAsyncError(async (req, res, next) => {
   try {
     let product = await Product.findById(req.params.id);

     //upload images//
     let images=[]

     if(req.body.imageCleared === 'false'){
        images = product.images;

     }
     if(req.files.length > 0){
         req.files.forEach(file => {
             let url = `${process.env.BACKEND_URL}/uploads/product/${file.originalname}`
             images.push({image:url})
         })
     }
     req.body.images = images;
     if(!product) {
         return res.status(404).json({
             success: false,
             message: "Product not found"
         });
     }
     product = await Product.findByIdAndUpdate(req.params.id, req.body),{

         new: true,
         runValidators: true
     }
     res.status(200).json({
        message: 'Product updated successfully'
     })
   } catch (error) {
    res.status(500).json({message: error.message})
    
   }
})

//Delete Product - api/v1/product/:id
exports.deleteProduct = catchAsyncError(async (req, res, next) =>{
    try {
        const product =await Product.findById(req.params.id);
        if(!product) {
            return res.status(404).json({
                success: false,
                message: "Product not found"
            });

        }
        await product.deleteOne();
        res.status(200).json({
            success: true,
            message: "Product deleted successfully"
        });
    } catch (error) {
        res.status(500).json({message: error.message})
        
    }
})
   

//Create Review - api/v1/review
exports.createReview = catchAsyncError(async (req, res, next) =>{
    const  { productId, rating, comment } = req.body;

    const review = {
        user : req.userId,
        rating,
        comment
    }

    const product = await Product.findById(productId);
   //finding user review exists
    const isReviewed = product.reviews.find(review => {
       return review.user.toString() == req.userId.toString()
    })

    if(isReviewed){
        //updating the  review
        product.reviews.forEach(review => {
            if(review.user.toString() == req.userId.toString()){
                review.comment = comment
                review.rating = rating
            }

        })

    }else{
        //creating the review
        product.reviews.push(review);
        product.numOfReviews = product.reviews.length;
    }
    //find the average of the product reviews
    product.ratings = product.reviews.reduce((acc, review) => {
        return review.rating + acc;
    }, 0) / product.reviews.length;
    product.ratings = isNaN(product.ratings)?0:product.ratings;

    await product.save({validateBeforeSave: false});

    res.status(200).json({
        success: true,
        message: 'Review created successfully',
        review
    })


})

//Get Reviews - api/v1/reviews?id={productId}
exports.getReviews = catchAsyncError(async (req, res, next) => {
    // Retrieve the product by ID
    const product = await Product.findById(req.query.id).populate('reviews.user','name email');

    // Check if the product exists
    if (!product) {
        return res.status(404).json({
            success: false,
            message: 'Product not found'
        });
    }

    // Return the reviews
    res.status(200).json({
        success: true,
        reviews: product.reviews
    });
});

//Delete Review - api/v1/review
exports.deleteReview = catchAsyncError(async (req, res, next) =>{
    const product = await Product.findById(req.query.productId);
    
    //filtering the reviews which does match the deleting review id
    const reviews = product.reviews.filter(review => {
       return review._id.toString() !== req.query.id.toString()
    });
    //number of reviews 
    const numOfReviews = reviews.length;

    //finding the average with the filtered reviews
    let ratings = reviews.reduce((acc, review) => {
        return review.rating + acc;
    }, 0) / reviews.length;
    ratings = isNaN(ratings)?0:ratings;

    //save the product document
    await Product.findByIdAndUpdate(req.query.productId, {
        reviews,
        numOfReviews,
        ratings
    })
    res.status(200).json({
        success: true
    })


});

// get admin products  - api/v1/admin/products
exports.getAdminProducts = catchAsyncError(async (req, res, next) => {
    const products = await Product.find();
    
    if (products.length === 0) {
        return res.status(404).json({
            success: false,
            message: "No products found."
        });
    }
    res.status(200).json({
        success: true,
        products
    });
});