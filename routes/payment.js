const express = require('express');

const { isAuthenticatedUser} = require('../middleware/authenticate');
const { sendStripeApi, processPayment } = require('../controllers/paymentcontrol');
const router = express.Router();

router.route('/payment/process').post( isAuthenticatedUser, processPayment);
router.route('/stripeapi').get( isAuthenticatedUser, sendStripeApi);


module.exports = router;