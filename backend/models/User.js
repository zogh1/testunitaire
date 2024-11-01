const mongoose = require('mongoose'); 

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: false }, // Make password optional
  role: {
    type: String,
    enum: ['User', 'Chercheur', 'Décideurs politiques', 'Agriculteurs', 'admin'],
    default: 'user'
  },
  verified: { type: Boolean, default: false },
  verificationToken: { type: String },
  resetPasswordToken: { type: String },
  resetPasswordExpires: { type: Date },
  twoFactorSecret: { type: String },
  organization: { type: String, required: false },
  position: { type: String, required: false },
  phone: { type: String, required: false },
  location: { type: String, required: false },
  specialization: { type: String, required: false },
  projects: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Project' }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }, // Track user updates
  status: {
    type: String,
    enum: ['active', 'inactive', 'suspended', 'banned'], // Add 'banned' as a possible status
    default: 'active'
  }
});

// Middleware to update the updatedAt field on save
UserSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

module.exports = mongoose.model('User', UserSchema);
