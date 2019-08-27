const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');

const User = require('../models/User');

// @route   POST  api/users
// @desc    Register a user
// @access  Public
router.post(
  '/',
  // express-validator checks
  [
    check('name', 'Please add name')
      .not()
      .isEmpty(),
    check('email', 'Please include a valid wmail').isEmail(),
    check(
      'password',
      'Please enter a password with 6 or more characters'
    ).isLength({ min: 6 })
  ],
  // Rest of function
  async (req, res) => {
    // Set error variable to results of the above checks
    const errors = validationResult(req);

    // If the errors variable is not empty, meaning if the above checks produced errors
    if (!errors.isEmpty()) {
      // Return errors
      return res.status(400).json({ errors: errors.array() });
    }

    // Carry on with rest of function

    // Destructure variables from req.body
    const { name, email, password } = req.body;

    try {
      // Check if user already exists by trying to find a matching email in DB
      let user = await User.findOne({ email });

      // If user does already exist send appropriate response
      if (user) {
        res.status(400).json({ msg: 'User already exists' });
      }

      // Otherwise create a new User
      user = new User({ name, email, password });

      // Password hashing, NEVER store plain text passwords in a db
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);

      await user.save();

      const payload = {
        user: {
          id: user.id
        }
      };

      jwt.sign(
        payload,
        config.get('jwtSecret'),
        {
          expiresIn: 360000
        },
        (err, token) => {
          if (err) {
            throw err;
          }
          res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server Error');
    }
  }
);

module.exports = router;
