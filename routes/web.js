const homeController = require('../app/http/controllers/homeController');
const authController = require('../app/http/controllers/authController');
const cartController = require('../app/http/controllers/customers/cartController');
const orderController = require('../app/http/controllers/customers/orderController');
const adminOrderController = require('../app/http/controllers/admin/orderController');
const statusController = require('../app/http/controllers/admin/statusController');

// Middlewares
const guest = require('../app/http/middlewares/guest');
const auth = require('../app/http/middlewares/auth');
const admin = require('../app/http/middlewares/admin');

function initRoutes(app) {
    // Public routes
    app.get('/', homeController().index);

    app.get('/login', guest, authController().login);
    app.post('/login', authController().postLogin);
    app.get('/register', guest, authController().register);
    app.post('/register', authController().postRegister);
    app.get('/logout', authController().logout);
    app.post('/logout', authController().logout);

    app.get('/cart', cartController().index);
    app.post('/update-cart', cartController().update);

    // Customer routes
    app.post('/orders', auth, orderController().store);
    app.get('/customer/orders', auth, orderController().index);
    app.get('/customer/orders/:id', auth, orderController().show);

    // Admin routes (moved inside the initRoutes function)
    app.get('/admin/orders', admin, adminOrderController().index);
    app.post('/admin/orders/status', admin, statusController().update);
}

module.exports = initRoutes;
