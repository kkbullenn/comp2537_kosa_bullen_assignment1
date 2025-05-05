const mongoose = require('mongoose');
const { hashPassword } = require('../schema');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { 
    type: String, 
    required: true, 
    unique: true,
    lowercase: true,
    trim: true
  },
  password: { type: String, required: true }
});

userSchema.pre('save', async function(next) {
   
    if (!this.isModified('password') || 
        this.password.startsWith('$2a$') || 
        this.password.startsWith('$2b$')) {
      return next();
    }
  
    try {
      this.password = await hashPassword(this.password);
      next();
    } catch (err) {
      next(err);
    }
  });

module.exports = mongoose.model('User', userSchema);