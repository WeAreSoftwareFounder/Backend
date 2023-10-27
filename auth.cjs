const JWT_SECRET = process.env.JWT_SECRET; // This has to be the same key used in the JWTStrategy

const jwt = require('jsonwebtoken'),
  passport = require('passport');

require('./passport.cjs'); // Your local passport file

let generateJWTToken = (user) => {
  return jwt.sign(user, JWT_SECRET, {
    subject: user.Username, // This is the username you’re encoding in the JWT
    expiresIn: '7d', // This specifies that the token will expire in 7 days
    algorithm: 'HS256', // This is the algorithm used to “sign” or encode the values of the JWT
  });
};

/* POST login. */
module.exports = (router) => {
  router.post('/login', (req, res) => {
    passport.authenticate(
      'local',
      { session: false },
      (error, Users, info) => {
        if (error || !Users) {
          return res.status(400).json({
            message: 'Something is not right',
            Users: Users,
          });
        }
        req.login(Users, { session: false }, (error) => {
          if (error) {
            res.send(error);
          }
          let token = generateJWTToken(Users.toJSON());
          return res.json({ Users, token });
        });
      }
    )(req, res);
  });
};
