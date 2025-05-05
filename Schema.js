const bcrypt = require('bcrypt');
const Joi = require('joi');

const hashPassword = async (password) => {
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
};

const comparePassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword);
};

const schemas = {
    user: Joi.object({
      name: Joi.string()
        .min(2)
        .max(50)
        .required()
        .pattern(/^[a-zA-Z\s]+$/)
        .messages({
          'string.pattern.base': 'Name can only contain letters and spaces',
          'string.empty': 'Name is required',
          'string.min': 'Name must be at least 2 characters long',
          'string.max': 'Name cannot exceed 50 characters'
        }),
      email: Joi.string()
        .email({ minDomainSegments: 2, tlds: { allow: false } })
        .required()
        .messages({
          'string.email': 'Please enter a valid email address',
          'string.empty': 'Email is required'
        }),
      password: Joi.string()
        .min(6)
        .max(30)
        .required()
        .messages({
          'string.empty': 'Password is required',
          'string.min': 'Password must be at least 6 characters long',
          'string.max': 'Password cannot exceed 30 characters'
        })
    }),
    login: Joi.object({
      email: Joi.string()
        .email({ minDomainSegments: 2 })
        .required()
        .messages({
          'string.email': 'Please enter a valid email address',
          'string.empty': 'Email is required'
        }),
      password: Joi.string()
        .required()
        .messages({
          'string.empty': 'Password is required'
        })
    })
  };
  

module.exports = {
  hashPassword,
  comparePassword,
  schemas
};