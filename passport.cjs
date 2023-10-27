const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const jwt = require('jsonwebtoken'); // Import the jsonwebtoken library
const Models = require('./models.cjs');
const passportJWT = require('passport-jwt');
require('dotenv').config(); // Import dotenv to use environment variables

let Users = Models.User,
  JWTStrategy = passportJWT.Strategy,
  ExtractJWT = passportJWT.ExtractJwt;

passport.use(
  new LocalStrategy(
    {
      usernameField: 'Username',
      passwordField: 'Password',
    },
    async (username, password, callback) => {
      console.log(`${username} ${password}`);
      await Users.findOne({ Username: username })
        .then((user) => {
          if (!user) {
            console.log('incorrect username');
            return callback(null, false, {
              message: 'Incorrect username or password.',
            });
          }
          if (!user.validatePassword(password)) {
            console.log('incorrect password');
            return callback(null, false, {
              message: 'Incorrect password.',
            });
          }

          // Generate a JWT token and send it as part of the response
          const token = jwt.sign(
            { _id: user._id, username: user.Username },
            process.env.JWT_SECRET, // Use your JWT secret from environment variables
            { expiresIn: '1h' }
          );

          console.log('finished');
          return callback(null, user, { token }); // Include the token in the response
        })
        .catch((error) => {
          if (error) {
            console.log(error);
            return callback(error);
          }
        });
    }
  )
);

passport.use(
  new JWTStrategy(
    {
      jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_SECRET , // Fetch the JWT secret from environment variables
    },
    async (jwtPayload, callback) => {
      console.log('JWT Payload:', jwtPayload); // Debugging line
      return await Users.findById(jwtPayload._id)
        .then((user) => {
          console.log('User found:', user); // Debugging line
          return callback(null, user);
        })
        .catch((error) => {
          console.log('Error:', error); // Debugging line
          return callback(error);
        });
    }
  )
);
