const express = require('express');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const cors = require('cors');
const { check, validationResult } = require('express-validator');
const { Movie, User } = require('./models.cjs');
const passport = require('passport');

const app = express();

const allowedOrigins = [
  'http://localhost:1234',
  'https://my-flixs-8361837988f4.herokuapp.com',
  'https://my-flixs-8361837988f4.herokuapp.com/login',
  'https://my-flixs-8361837988f4.herokuapp.com/movies',
  'https://my-flixs-8361837988f4.herokuapp.com/users',
  // ...other origins
];

// Create a custom CORS middleware function
const corsOptions = {
  origin: (origin, callback) => {
    // Check if the environment is production
    const isProduction = process.env.NODE_ENV === 'production';

    if (
      !origin ||
      (isProduction && allowedOrigins.indexOf(origin) !== -1)
    ) {
      // If origin is undefined or it's a valid origin (including localhost during development)
      callback(null, true);
    } else {
      // Invalid origin for production
      let message =
        'The CORS policy for this application doesn’t allow access from origin ' +
        origin;
      callback(new Error(message), false);
    }
  },
};

app.use(cors(corsOptions));

app.use(cors(corsOptions));
app.use(morgan('tiny'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

mongoose
  .connect(process.env.CONNECTION_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((error) => {
    console.error('Error connecting to MongoDB:', error);
  });

require('./passport.cjs');
require('./auth.cjs')(app);

// Landing page
app.get('/', (req, res) => {
  res.json({ message: 'Welcome to My Flix' });
});

// Validation for Username (express-validator)
check(
  'Username',
  'Username contains non-alphanumeric characters - not allowed.'
).isAlphanumeric();

// Logging endpoints

// Handle the login route
const loginValidation = [
  check('Username', 'Username is required').notEmpty(),
  check('Password', 'Password is required').notEmpty(),
];

app.post('/login', loginValidation, (req, res) => {
  // Authentication logic goes here
  // You can access the validated request body with req.body
  const { Username, Password } = req.body;

  User.findOne({ Username })
    .then((user) => {
      if (!user || !user.validatePassword(Password)) {
        return res.status(401).json({ error: 'Invalid credentials' }); // Return an error object in JSON format
      }

      const token = generateJWTToken(user.toJSON());
      res.status(200).json({ user, token });
    })
    .catch((error) => {
      console.error(error);
      res.status(500).json({ error: 'Internal server error' }); // Return an error object in JSON format
    });
});

// Middleware for JWT authentication
const authenticateJWT = passport.authenticate('jwt', {
  session: false,
});

// Gets all movies
app.get('/movies', authenticateJWT, async (req, res) => {
  try {
    const movies = await Movie.find();
    res.status(201).json(movies);
  } catch (error) {
    console.error(error);
    res.status(500).send('Error: ' + error);
  }
});
app.get('/movies/:id', async (req, res) => {
  try {
    const movie = await Movie.findById(req.params.id);
    if (!movie) {
      return res.status(404).send('Movie not found');
    }
    res.json(movie);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error: ' + err);
  }
});

// Gets movie by name
app.get('/movies/:title', async (req, res) => {
  try {
    const movie = await Movie.findOne({ Title: req.params.title });
    res.json(movie);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error: ' + err);
  }
});

// Gets movies by Genre
app.get('/movies/genres/:genreName', async (req, res) => {
  try {
    const movies = await Movie.find({
      'Genre.Name': req.params.genreName,
    });
    res.json(movies);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error: ' + err);
  }
});

// Gets Director Info by name
app.get('/directors/:directorName', async (req, res) => {
  try {
    const movies = await Movie.find({
      'Director.Name': req.params.directorName,
    });
    res.json(movies);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error: ' + err);
  }
});

// Gets all users
app.get('/users', async (req, res) => {
  try {
    const users = await User.find();
    res.status(201).json(users);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error: ' + err);
  }
});

// Get a user by username
app.get('/users/:username', async (req, res) => {
  try {
    const user = await User.findOne({ Name: req.params.username });
    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error: ' + err);
  }
});

// Creates a new user
app.post(
  '/users',
  [
    check('Username', 'Username is required').isLength({ min: 5 }),
    check(
      'Username',
      'Username contains non-alphanumeric characters - not allowed.'
    ).isAlphanumeric(),
    check('Password', 'Password is required').not().isEmpty(),
    check('Email', 'Email does not appear to be valid').isEmail(),
  ],
  async (req, res) => {
    try {
      let hashedPassword = User.hashPassword(req.body.Password);

      const existingUser = await User.findOne({
        Username: req.body.Username,
      });

      if (existingUser) {
        return res
          .status(400)
          .send(req.body.Username + ' already exists');
      }

      const newUser = await User.create({
        Username: req.body.Username,
        Password: hashedPassword,
        Email: req.body.Email,
        Birthday: req.body.Birthday,
      });

      res.status(201).json(newUser);
    } catch (error) {
      console.error(error);
      res.status(500).send('Error: ' + error.message);
    }
  }
);

// Updates User
app.put('/users/:username', authenticateJWT, async (req, res) => {
  if (req.user.Username !== req.params.username) {
    return res.status(400).send('Permission denied');
  }

  try {
    const updatedUser = await User.findOneAndUpdate(
      { Username: req.params.username },
      {
        $set: {
          Username: req.body.Username,
          Password: req.body.Password,
          Email: req.body.Email,
          Birthday: req.body.Birthday,
          Role: req.body.Role,
          FavoriteMovies: req.body.FavoriteMovies,
        },
      },
      { new: true }
    );
    res.json(updatedUser);
  } catch (err) {
    console.log(err);
    res.status(500).send('Error: ' + err);
  }
});

// Add a movie to a user's list of favorites
app.post('/users/:Username/movies/:movieID', async (req, res) => {
  try {
    const updatedUser = await User.findOneAndUpdate(
      { Username: req.params.Username },
      {
        $push: { FavoriteMovies: req.params.movieID },
      },
      { new: true }
    );
    res.json(updatedUser);
  } catch (err) {
    console.error(err);
    res.status(500).send(`$Error:` + err);
  }
});

// Remove User Movie
app.post(
  '/users/:Username/movies/remove/:MovieID',
  async (req, res) => {
    try {
      // Extract parameters from the request
      const { Username, MovieID } = req.params;

      // Check if Username and MovieID are valid (e.g., not undefined)
      if (!Username || !MovieID) {
        return res
          .status(400)
          .json({ message: 'Invalid parameters' });
      }

      // Your logic to remove the movie from the user's list of favorites
      // ...

      res
        .status(200)
        .json({ message: 'Movie Removed from user list' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Error: ' + err });
    }
  }
);

// Delete user Account
app.delete('/users/:Username', async (req, res) => {
  try {
    const user = await User.findOneAndRemove({
      Username: req.params.Username,
    });
    if (!user) {
      res.status(400).send(req.params.Username + ' was not found');
    } else {
      res.status(200).send(req.params.Username + ' was deleted.');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Error: ' + err);
  }
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: 'Internal server error' });
});

mongoose.connection.once('open', () => {
  console.log('Connected to mongoDB');
  const port = process.env.PORT;
  app.listen(port, () => {
    console.log('Server running');
  });
  mongoose.set('debug', true);
});
