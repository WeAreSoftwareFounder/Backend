const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const movieSchema = new mongoose.Schema({
  Title: { type: String, required: true },
  Description: { type: String, required: true },
  Genre: {
    Name: String,
    Description: String,
  },
  Director: {
    Name: String,
    Bio: String,
  },
  Actors: [String],
  ImagePath: String,
  Featured: Boolean,
});

const userSchema = new mongoose.Schema({
  Username: { type: String, required: true },
  Password: { type: String, required: true },
  Email: { type: String, required: true },
  Birthday: Date,
  FavoriteMovies: [
    { type: mongoose.Schema.Types.ObjectId, ref: 'Movie' },
  ],
});

// Define a static method to hash the user's password
userSchema.statics.hashPassword = function (password) {
  return bcrypt.hashSync(password, 10); // Synchronous hashing for simplicity
};

// Define a method to validate the user's password
userSchema.methods.validatePassword = function (password) {
  return bcrypt.compareSync(password, this.Password); // Use uppercase "P" for Password
};

const Movie = mongoose.model('Movie', movieSchema, 'Movies');
const User = mongoose.model('User', userSchema, 'Users');

module.exports = { Movie, User };
