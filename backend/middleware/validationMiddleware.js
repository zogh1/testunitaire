const { body } = require('express-validator');
const User = require('../models/User');

exports.validateRegister = [
  body('name')
    .notEmpty()
    .withMessage('Name is required')
    .isAlpha('en-US', { ignore: ' ' })
    .withMessage('Name should only contain letters and spaces'),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please enter a valid email address')
    .custom(async (value) => {
      const user = await User.findOne({ email: value });
      if (user) {
        throw new Error('This email address is already in use');
      }
    }),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long'),
  body('organization')
    .notEmpty()
    .withMessage('Organization is required'),
  body('position')
    .notEmpty()
    .withMessage('Position is required'),
  body('phone')
    .notEmpty()
    .withMessage('Phone number is required')
    .isMobilePhone()
    .withMessage('Please enter a valid phone number'),
  body('location')
    .notEmpty()
    .withMessage('Location is required'),
  body('specialization')
    .notEmpty()
    .withMessage('Specialization is required')
];

exports.validateResetPassword = [
  body('token')
    .notEmpty()
    .withMessage('Token is required'),
  body('newPassword')
    .isLength({ min: 6 })
    .withMessage('New password must be at least 6 characters long')
];

exports.validateSignIn = [
  body('email')
    .isEmail()
    .withMessage('Please enter a valid email address'),
  body('password')
    .exists()
    .withMessage('Password is required')
];

exports.validateUpdateUser = [
  body('name')
    .optional()
    .notEmpty()
    .withMessage('Name cannot be empty')
    .isAlpha('en-US', { ignore: ' ' })
    .withMessage('Name should only contain letters and spaces'),
  body('email')
    .optional()
    .isEmail()
    .normalizeEmail()
    .withMessage('Please enter a valid email address'),
  body('organization')
    .optional()
    .notEmpty()
    .withMessage('Organization cannot be empty'),
  body('position')
    .optional()
    .notEmpty()
    .withMessage('Position cannot be empty'),
  body('phone')
    .optional()
    .notEmpty()
    .withMessage('Phone number cannot be empty')
    .isMobilePhone()
    .withMessage('Please enter a valid phone number'),
  body('location')
    .optional()
    .notEmpty()
    .withMessage('Location cannot be empty'),
  body('specialization')
    .optional()
    .notEmpty()
    .withMessage('Specialization cannot be empty')
];
