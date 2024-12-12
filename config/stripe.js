const dotenv = require  ('dotenv');
const stripePackage = require ('stripe');


dotenv.config();
exports.stripe =new stripePackage(process.env.STRIPE_SECRET_KEY);

