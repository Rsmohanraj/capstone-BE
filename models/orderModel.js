const mongoose = require('mongoose');

const orderSchema = mongoose.Schema({
  orderItems: [
    {
      product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
      name: { type: String, required: true },
      image: { type: String, required: true },
      quantity: { type: Number, required: true },
      price: { type: Number, required: true },
    },
  ],
  shippingInfo: {
    address: { type: String, required: true },
    city: { type: String, required: true },
    phoneNo: { type: String, required: true },  // Changed to String for phone number
    postalCode: { type: String, required: true },
    country: { type: String, required: true },
  },
  itemsPrice: { type: Number, required: true },
  taxPrice: { type: Number, required: true },
  shippingPrice: { type: Number, required: true },
  totalPrice: { type: Number, required: true },
  paymentInfo: {
    id: { type: String, required: true },
    status: { type: String, required: true },
  },
  paidAt: { type: Date },
  orderStatus: { type: String, required: true, default: 'processing' },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  isDelivered: { type: Boolean, default: false },
  deliveredAt: { type: Date },
}, { timestamps: true });  // Automatically add createdAt and updatedAt fields

let orderModel = mongoose.model('Order', orderSchema);

module.exports = orderModel;
