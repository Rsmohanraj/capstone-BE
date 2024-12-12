const express = require('express');
const { getProducts, getSingleProduct, updateProduct, deleteProduct, createReview, getReviews, deleteReview, getAdminProducts, newProduct} = require('../controllers/ProductControl');
const router = express.Router();
const {isAuthenticatedUser, isAuthenticateRole } = require('../middleware/authenticate')
const  multer =require('multer');
const path =require('path');

const upload = multer({storage:multer.diskStorage({
    destination:function(req,file,cb){
        cb(null,path.join(__dirname,'..', 'uploads/product'))
    },
    filename:function(req,file,cb){
        cb(null,file.originalname)
    }

})})

router.route('/products').get(getProducts);
//router.route('/Product/new').post(newProduct);
router.route('/Product/:id').get(getSingleProduct);


router.route('/review').put(isAuthenticatedUser,createReview)





//Admin routes//
router.route('/admin/product/new').post(isAuthenticatedUser, isAuthenticateRole ('admin'), upload.array('images'), newProduct);
router.route('/admin/product').get(isAuthenticatedUser, isAuthenticateRole ('admin'), getAdminProducts);
router.route('/admin/product/:id').delete(isAuthenticatedUser, isAuthenticateRole ('admin'), deleteProduct);
router.route('/admin/product/:id').put(isAuthenticatedUser, isAuthenticateRole ('admin'),upload.array('images'), updateProduct);
router.route('/admin/reviews').get(isAuthenticatedUser, isAuthenticateRole ('admin'),getReviews)
router.route('/admin/review').delete(isAuthenticatedUser, isAuthenticateRole ('admin'),deleteReview)


module.exports = router;