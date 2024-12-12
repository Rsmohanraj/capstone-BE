const express = require('express');
const { newOrder, 
    getSingleOrder, 
    myOrders, 
    orders, 
    updateOrder, 
    deleteOrder} = require('../controllers/ordercontrol');
const router = express.Router();
const {isAuthenticatedUser, isAuthenticateRole } = require('../middleware/authenticate');

router.route('/order/new').post(isAuthenticatedUser,newOrder);
router.route('/order/:id').get(isAuthenticatedUser,getSingleOrder);
router.route('/my/orders').get(isAuthenticatedUser,myOrders);

//Admin routes//
router.route('/admin/orders').get(isAuthenticatedUser,isAuthenticateRole ('admin'),orders)
router.route('/admin/order/:id').put(isAuthenticatedUser,isAuthenticateRole ('admin'),updateOrder)
router.route('/admin/order/:id').delete(isAuthenticatedUser,isAuthenticateRole ('admin'),deleteOrder)


module.exports = router;