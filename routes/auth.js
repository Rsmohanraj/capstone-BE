const express =require('express');
const multer = require('multer');
const path = require('path');


 const upload = multer({storage: multer.diskStorage({
    destination: function(req, file,cb){
        cb(null,path.join(__dirname,'..', 'uploads/user'));
    },
    filename: function(req, file, cb){
        cb(null,  file.originalname);
    }
})})

const { registerUser, 
    loginUser, 
    logoutUser, 
    forgetPassword, 
    resetPassword, 
    UserProfile,
    updateProfile,
    getAllUsers,
    getUser,
    updateUser,
    deleteUser} = require('../controllers/authcontrol');
const router =express.Router();
const { isAuthenticatedUser, isAuthenticateRole  } = require('../middleware/authenticate');

router.route('/register').post(upload.single('avatar'),registerUser);
router.route('/login').post(loginUser);
router.route('/logout').get(logoutUser);
router.route('/password/forget').post(forgetPassword);
router.route('/password/reset/:token').post(resetPassword);
router.route('/userprofile').get(isAuthenticatedUser,UserProfile);
router.route('/update').put(isAuthenticatedUser,updateProfile);


//Admin routes//
router.route('/admin/users').get(isAuthenticatedUser,isAuthenticateRole ('admin'),getAllUsers);
router.route('/admin/user/:id').get(isAuthenticatedUser,isAuthenticateRole ('admin'),getUser);
router.route('/admin/user/:id').put(isAuthenticatedUser,isAuthenticateRole ('admin'),updateUser);
router.route('/admin/user/:id').delete(isAuthenticatedUser,isAuthenticateRole ('admin'),deleteUser);


module.exports = router;