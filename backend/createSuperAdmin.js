require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const User = require('./models/User'); 
const connectDB = require('./config/db');


console.log("Admin Email:", process.env.ADMIN_EMAIL);
console.log("Admin Password:", process.env.ADMIN_PASSWORD);

// Connect to MongoDB
connectDB();

async function createSuperAdmin() {
  try {
    const adminExists = await User.findOne({ email: process.env.ADMIN_EMAIL });
    if (adminExists) {
      console.log('Admin already exists');
      return;
    }

    // Ensure that ADMIN_PASSWORD is defined
    if (!process.env.ADMIN_PASSWORD) {
      throw new Error('ADMIN_PASSWORD is not defined in the environment variables');
    }

    const saltRounds = 10;
    const hashedPassword = bcrypt.hashSync(process.env.ADMIN_PASSWORD, saltRounds);

    const admin = new User({
      name: 'Super Admin',
      email: process.env.ADMIN_EMAIL,
      password: hashedPassword,
      role: 'admin', // Ensure this is valid according to the schema
    });

    await admin.save();
    console.log('Super Admin created successfully');
  } catch (err) {
    console.error(`Error creating admin: ${err.message}`);
  } finally {
    mongoose.connection.close();
  }
}

createSuperAdmin();
