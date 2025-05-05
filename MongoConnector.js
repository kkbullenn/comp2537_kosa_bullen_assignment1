require('dotenv').config();
const mongoose = require('mongoose');

const host = process.env.MONGODB_HOST;
const user = process.env.MONGODB_USER;
const password = process.env.MONGODB_PASSWORD;

const connectDB = async () => {
  try {
    const encodedPassword = encodeURIComponent(password);
    const connectionString = `mongodb+srv://${user}:${encodedPassword}@${host}/retryWrites=true`;
    
    await mongoose.connect(connectionString, {
      serverSelectionTimeoutMS: 5000 
    });
  } catch (err) {
    console.error('MongoDB Connection Error:', err.message);
    process.exit(1);
  }
};

// Connection event handlers
mongoose.connection.on('connecting', () => console.log('Connecting to MongoDB...'));
mongoose.connection.on('connected', () => console.log('MongoDB connected'));
mongoose.connection.on('disconnected', () => console.log('MongoDB disconnected'));

module.exports = connectDB;