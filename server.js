// Express and Passport dependencies
var express = require('express');
var passport = require('passport');
var Strategy = require('passport-google-oauth20').Strategy;

// Validation and Sanitization dependencies
var { check, validationResult } = require('express-validator/check');
var helmet = require('helmet');
var sanitize = require('caja-html-sanitizer');

// File I/O dependencies
var fs = require('fs');
var path = require('path');

// User-defined variables and constants
const mottoLengthMax = process.env.APP_MOTTO_LENGTH_MAX;
const appDomain = process.env.APP_DOMAIN;
const appPort = process.env.APP_PORT;

/*
 * Configure the Google strategy for use by Passport.
 *
 * OAuth 2.0-based strategies require a 'verify' function which receives the
 * credential (`accessToken`) for accessing the Google API on the user's
 * behalf, along with the user's profile.  The function must invoke 'cb'
 * with a user object, which will be set at `req.user` in route handlers after
 * authentication.
 */
passport.use(new Strategy({
    clientID: process.env.APP_CLIENT_ID,
    clientSecret: process.env.APP_CLIENT_SECRET,
    callbackURL: 'http://' + appDomain + ':' + appPort + '/login/google/return',
    userProfileURL: 'https://www.googleapis.com/oauth2/v2/userinfo'
  },
  function(accessToken, refreshToken, profile, cb) {
  /*
   * In this example, the user's Google profile is supplied as the user
   * record.  In a production-quality application, the Google profile should
   * be associated with a user record in the application's database, which
   * allows for account linking and authentication with other identity
   * providers.
   */
    console.log('profile', profile);
    return cb(null, profile);
}));

/*
 * Configure Passport authenticated session persistence.
 *
 * In order to restore authentication state across HTTP requests, Passport needs
 * to serialize users into and deserialize users out of the session.  In a
 * production-quality application, this would typically be as simple as
 * supplying the user ID when serializing, and querying the user record by ID
 * from the database when deserializing.  However, due to the fact that this
 * example does not have a database, the complete Facebook profile is serialized
 * and deserialized.
 */
passport.serializeUser(function(user, cb) {
  cb(null, user);
});

passport.deserializeUser(function(obj, cb) {
  cb(null, obj);
});

// Create a new Express application.
var app = express();

// Configure view engine to render EJS templates.
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');

// Use application-level middleware for common functionality, including
// logging, parsing, and session handling.
app.use(require('morgan')('combined'));
app.use(require('cookie-parser')());
app.use(require('body-parser').urlencoded({ extended: true }));
app.use(require('express-session')({ secret: 'keyboard cat', resave: true, saveUninitialized: true }));

app.use(helmet());

// Initialize Passport and restore authentication state, if any, from the
// session.
app.use(passport.initialize());
app.use(passport.session());

// Define routes.
// Root
app.get('/',
  function(req, res) {
    res.render('home', { user: req.user });
  });

// Login nexus
app.get('/login',
  function(req, res){
    res.render('login');
  });

// Login: Google
app.get('/login/google',
        passport.authenticate('google', { scope: ['profile'] }));

// Login: Google return
app.get('/login/google/return',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/');
  });

// Profile retrieval
app.get('/profile',
  require('connect-ensure-login').ensureLoggedIn(),
  function(req, res) {
        var mottofile = path.join(__dirname, 'data', req.user._json.id + '.txt');
        var motto;
        try {
            motto = fs.readFileSync(mottofile);
        } catch (err) {
            motto = "";
        }
        motto = sanitize(motto);
        res.render('profile', { user: req.user, motto: motto });
  });

// Profile update
app.post('/profile',
        require('connect-ensure-login').ensureLoggedIn(),
        function(req, res){
        var errors = validationResult(req)
        var mottofile = path.join(__dirname, 'data', req.user._json.id + '.txt');
        var motto = sanitize(req.body.motto.trim().substring(0, mottoLengthMax));
        res.render('profile', { user: req.user, motto: motto, errors: errors.mapped() });
        fs.writeFileSync(mottofile, motto);
        });

// Logout
app.get('/logout', function(req, res) {
    req.logOut();
    res.redirect('/');
  });

app.listen(appPort);
