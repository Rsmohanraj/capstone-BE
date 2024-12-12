//create new order//

const ErrorHandler = require('../Utils/errorHandler');
const catchAsyncError = require('../middleware/catchAsyncError');
const Order = require('../models/orderModel');
const Product = require('../models/ProductModel')

exports.newOrder =catchAsyncError(async(req, res, next) => {
    const{
        orderItems,
        shippingInfo,
        itemsPrice,
        taxPrice,
        shippingPrice,
        totalPrice,
        paymentInfo,
        
    } =req.body;

    const order =await Order.create({
        orderItems,
        shippingInfo,
        itemsPrice,
        taxPrice,
        shippingPrice,
        totalPrice,
        paymentInfo,
        paidAt:Date.now(),
        user: req.userId
    
});
res.status(200).json({
    success: true,
    order
})

})

//get single orders//

exports.getSingleOrder = async(req, res, next) =>{
    const order = await Order.findById(req.params.id).populate('user','name email');
    if(!order){
     
       return next(new ErrorHandler(`orders not found ${req.params.id}`,400));
    }
    res.status(201).json({
        success : true,
        order
    })
}

//get Logged in users//
exports.myOrders = async(req, res, next) =>{
    const orders = await Order.find({user:req.userId});
   
    res.status(201).json({
        success : true,
        orders
    })
}

//Admin : get all orders//
exports.orders = async(req, res, next) =>{
    const orders = await Order.find();

    let totalAmount = 0;
    orders.forEach(order => {
        totalAmount += order.totalPrice;
    });
   
    res.status(201).json({
        success : true,
        totalAmount,
        orders
    })
}
//update order/order status //
exports. updateOrder = (async (req,res,next) => {
    const order =await Order.findById(req.params.id);


    if(order.orderStatus === 'Delivered'){
        return next(new ErrorHandler('order has be already delivered order', 400));
    }
    //update stock//
    order.orderItems.forEach(async orderItem => {
        await updateStock(orderItem.product,orderItem.quantity)
        
    });

    order.orderStatus = req.body.orderStatus;
    order.deliveredAt = Date.now();
    await order.save();

    res.status(200).json({
        success: true,
        order
       
    });


});


//helper function to update stock//
const updateStock = async(productId, quantity) => {
    const product = await Product.findByIdAndUpdate(productId, {
        $inc: { stock: -quantity }
    }, { new: true });

    
}



// Admin delete order//
exports.deleteOrder =catchAsyncError(async(req, res, next) => {
    const order = await Order.findById(req.params.id);
    if(!order){
      return next(new ErrorHandler(`No order found with that id ${req.params.id}`));
    }
    await order.deleteOne();
    res.status(200).json({
        success: true,
        message: 'Order deleted successfully'
    })
 });