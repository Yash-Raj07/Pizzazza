const User = require('../../models/user');
const bcrypt = require('bcrypt');
const passport = require('passport');

function authController() {
  const _getRedirectUrl=(req)=>{
    return req.user.role==='admin'?'/admin/orders':'/customer/orders'
  }
  return {
    login(req, res) {
      res.render('auth/login');
    },
    postLogin(req, res, next) {
      const { email, password}= req.body
      //validate request
      if(!email || !password){
        req.flash('error', 'All fields are required'
          
        )
        return res.redirect('/login')
      }
      passport.authenticate('local', (err, user, info) => {
        if (err) {
          req.flash('error', info.message);
          return next(err);
        }
        if (!user) {
          req.flash('error', info.message);
          return res.redirect('/login');
        }
        req.login(user, (err) => {
          if (err) {
            req.flash('error', info.message);
            return next(err);
          }
          return res.redirect(_getRedirectUrl(req)); 
        });
      })(req, res, next);
    },
    register(req, res) {
      res.render('auth/register');
    },
    async postRegister(req, res) {
      const { name, city, state, email, password } = req.body;

      // Validate request
      if (!name || !city || !state || !email || !password) {
        req.flash('error', 'All fields are required');
        req.flash('name', name);
        req.flash('city', city);
        req.flash('state', state);
        req.flash('email', email);
        return res.redirect('/register');
      }

      // Check if email exists
      const userExists = await User.exists({ email: email });
      if (userExists) {
        req.flash('error', 'Email already taken');
        req.flash('name', name);
        req.flash('city', city);
        req.flash('state', state);
        req.flash('email', email);
        return res.redirect('/register');
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create a user
      const user = new User({
        name,
        city,
        state,
        email,
        password: hashedPassword
      });

      await user.save(); // Save the user to the database

      res.redirect('/login'); // Redirect to the login page after successful registration
    },
    logout(req, res, next) {
      req.logout(function(err) {
        if (err) {
          return next(err);
        }
        return res.redirect('/login');
      });
    }
  };
}

module.exports = authController;
