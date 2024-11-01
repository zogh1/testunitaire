// backend/controllers/userController.js

require('dotenv').config();
const transporter = require('../config/emailConfig');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const imaps = require('imap-simple');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const { body } = require('express-validator');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const { validationResult } = require('express-validator');
const path = require('path');
const { SOGO_IMAP_SERVER, IMAP_PORT, JWT_SECRET, API_ENDPOINT } = process.env;
const { authMiddleware, isAdmin, logAction } = require('../middleware/auditLogMiddleware');
const fs = require('fs'); 

const Mailjet = require('node-mailjet');



const mailjet = Mailjet.apiConnect(
  process.env.MAILJET_API_KEY,
  process.env.MAILJET_SECRET_KEY
);
const sendVerificationEmail = async (email, verificationToken) => {
    try {
      const verificationURL = `${process.env.API_ENDPOINT}/api/users/verify/${verificationToken}`;
      const logoImageUrl ='https://i.postimg.cc/YCykgfQF/unnamed.png'

  
      const request = await mailjet
        .post('send', { version: 'v3.1' })
        .request({
          Messages: [
            {
              From: {
                Email: process.env.EMAIL_USER,
                Name: 'La Chaire de Biotechnologie',
              },
              To: [{ Email: email }],
              Subject: 'Vérification de votre adresse email',
              HTMLPart: `
                <div style="font-family: Arial, sans-serif; text-align: center;">
                  <img src="${logoImageUrl}" alt="La Chaire de Biotechnologie" style="width: 200px; margin-bottom: 20px;" />
                  <h2>Bonjour,</h2>
                  <p>Merci de vous être inscrit !</p>
                  <p>Veuillez <a href="${verificationURL}" style="color: #1a73e8; text-decoration: none;">cliquer ici</a> pour vérifier votre adresse email.</p>
                  <p>Merci,</p>
                  <p>La Chaire de Biotechnologie</p>
                </div>
              `,
            },
          ],
        });
  
      console.log(`Verification email sent to ${email}`);
    } catch (err) {
      console.error(`Error sending verification email to ${email}: ${err.message}`);
      throw new Error(`Failed to send verification email to ${email}`);
    }
  };
  
  

// Helper function to authenticate with SOGo
const authenticateWithSogo = async (email, password) => {
    const config = {
        imap: {
            user: email,
            password: password,
            host: SOGO_IMAP_SERVER,
            port: IMAP_PORT || 993,
            tls: true,
            authTimeout: 5000,
        }
    };

    try {
        const connection = await imaps.connect({ imap: config.imap });
        await connection.openBox('INBOX');
        connection.end();
        return true;
    } catch (error) {
        console.error('IMAP Authentication failed:', error.message);
        return false;
    }
};

// Register with SOGo
exports.registerWithSogo = async (req, res) => {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
        return res.status(400).json({ message: 'Name, email, and password are required.' });
    }

    try {
        const isAuthenticated = await authenticateWithSogo(email, password);

        if (!isAuthenticated) {
            return res.status(401).json({ message: 'Authentication with SOGo failed.' });
        }

        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'User already exists.' });
        }

        user = new User({
            name,
            email,
            password,
        });

        await user.save();
        res.status(201).json({ message: 'User registered successfully with SOGo authentication.' });
    } catch (error) {
        console.error('Error in registerWithSogo:', error.message);
        res.status(500).json({ message: 'An error occurred during registration.' });
    }
};

// Sign in with SOGo
exports.signInWithSOGo = async (req, res) => {
    const { email, password } = req.body;

    try {
        const imapAuthenticated = await authenticateWithSogo(email, password);

        if (!imapAuthenticated) {
            return res.status(401).json({ msg: 'Invalid credentials' });
        }

        let user = await User.findOne({ email });
        if (!user) {
            user = new User({
                email,
                name: email.split('@')[0],
                verified: true,
                role: 'user'
            });
            await user.save();
        }

        const payload = {
            user: {
                id: user.id,
                role: user.role
            },
        };

        jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;
            res.json({
                token,
                user: {
                    name: user.name,
                    email: user.email,
                    role: user.role
                }
            });
        });
    } catch (err) {
        console.error('IMAP Authentication failed:', err.message);
        res.status(401).json({ msg: 'Invalid credentials' });
    }
};
   


// Validation middleware
exports.validateRegister = [
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Email is not valid')
        .custom(async (value) => {
            const user = await User.findOne({ email: value });
            if (user) {
                throw new Error('Cette adresse email est déjà utilisée');
            }
        }),
    body('name')
        .matches(/^[\p{L}\s]+$/u)
        .withMessage('Name cannot contain numbers or special characters')
        .trim()
        .escape(),
    body('password')
        .isLength({ min: 6 })
        .withMessage('Le mot de passe doit contenir au moins 6 caractères'),
];


exports.validateResetPassword = [
    body('token').notEmpty().withMessage('Le token est requis'),
    body('newPassword').isLength({ min: 6 }).withMessage('Le nouveau mot de passe doit contenir au moins 6 caractères')
];
exports.registerUser = async (req, res) => {
    console.log('Incoming request body:', req.body);
    const { name, email, password, role, organization, position, phone, location, specialization } = req.body;

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.log('Validation errors:', errors.array());
        return res.status(400).json({ errors: errors.array() });
    }

    const validRoles = ['User', 'Chercheur', 'Décideurs politiques', 'Agriculteurs'];
    if (!validRoles.includes(role)) {
        return res.status(400).json({ msg: 'Invalid role provided' });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists.' });
        }

        const verificationToken = crypto.randomBytes(20).toString('hex');
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            name,
            email,
            password: hashedPassword,
            role,
            verified: false,
            verificationToken,
            organization,
            position,
            phone,
            location,
            specialization,
            status: 'active'
        });

        await newUser.save();
        await sendVerificationEmail(email, verificationToken);

        return res.status(201).json({ msg: 'User registered. Please check your email for verification.' });
    } catch (err) {
        console.error('Error during user registration:', err.message);
        return res.status(500).send('Server Error');
    }
};



// Check if email exists
exports.checkEmail = async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (user) {
            return res.json({ exists: true });
        } else {
            return res.json({ exists: false });
        }
    } catch (err) {
        console.error('Error checking email:', err.message);
        res.status(500).send('Server Error');
    }
};

// Verify email
exports.verifyEmail = async (req, res) => {
    const token = req.params.token;

    try {
        let user = await User.findOne({ verificationToken: token });

        if (!user) {
            return res.status(400).json({ msg: 'Invalid token or user not found' });
        }

        user.verified = true;
        user.verificationToken = undefined;
        await user.save();

        res.json({ msg: 'Email verified successfully. You can now login.' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
};

const sendPasswordResetEmail = async (email, resetPasswordToken) => {
    try {
      const resetURL = `http://localhost:3000/reset-password/${resetPasswordToken}`; // Frontend URL
      const imageURL = 'https://i.postimg.cc/YCykgfQF/unnamed.png'
  
      const request = await mailjet
        .post('send', { version: 'v3.1' })
        .request({
          Messages: [
            {
              From: {
                Email: process.env.EMAIL_USER,
                Name: 'La Chaire de Biotechnologie',
              },
              To: [{ Email: email }],
              Subject: 'Réinitialisation de votre mot de passe',
              HTMLPart: `
                <div style="font-family: Arial, sans-serif; text-align: center;">
                  <img src="${imageURL}" alt="La Chaire de Biotechnologie" style="width: 150px; height: auto; margin-bottom: 20px;" />
                  <h2>Réinitialisation de votre mot de passe</h2>
                  <p>Vous avez demandé la réinitialisation de votre mot de passe.</p>
                  <p>Veuillez <a href="${resetURL}" style="color: #1a73e8; text-decoration: none;">cliquer ici</a> pour réinitialiser votre mot de passe.</p>
                  <p>Ce lien est valide pendant une heure.</p>
                  <p>Merci,</p>
                  <p>La Chaire de Biotechnologie</p>
                </div>
              `,
            },
          ],
        });
  
      console.log(`Password reset email sent to ${email}`);
    } catch (err) {
      console.error(`Error sending password reset email to ${email}: ${err.message}`);
      throw new Error(`Failed to send password reset email to ${email}`);
    }
};

  
  
  exports.forgotPassword = async (req, res) => {
    const { email } = req.body;
  
    try {
      const resetPasswordToken = crypto.randomBytes(20).toString('hex');
      let user = await User.findOne({ email });
  
      if (!user) {
        return res.status(404).json({ msg: 'User not found' });
      }
  
      user.resetPasswordToken = resetPasswordToken;
      user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
      await user.save();
  
      await sendPasswordResetEmail(email, resetPasswordToken);
      res.json({ msg: 'Password reset email sent. Please check your email.' });
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server Error');
    }
  };
  
// Reset password
exports.resetPassword = async (req, res) => {
    const { token, newPassword } = req.body;

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        let user = await User.findOne({ resetPasswordToken: token, resetPasswordExpires: { $gt: Date.now() } });

        if (!user) {
            return res.status(400).json({ msg: 'Invalid or expired token' });
        }

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);

        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.json({ msg: 'Password reset successful. You can now login with your new password.' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
};

// Validation middleware for profile update
exports.validateUpdateProfile = [
    body('newPassword').optional().isLength({ min: 6 }).withMessage('Le nouveau mot de passe doit contenir au moins 6 caractères')
];

// Get user profile
exports.getUserProfile = async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        
        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }

        res.json(user);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
};

// Update user profile
exports.updateUserProfile = async (req, res) => {
    try {
        const userId = req.user.id;
        const updates = req.body;

        let user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }

        Object.keys(updates).forEach(key => {
            if (updates[key]) {
                user[key] = updates[key];
            }
        });

        if (updates.newPassword) {
            const salt = await bcrypt.genSalt(10);
            user.password = await bcrypt.hash(updates.newPassword, salt);
        }

        await user.save();
        res.json({ msg: 'User profile updated successfully', user });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
};

// Check user role middleware
exports.checkRole = (roles) => async (req, res, next) => {
    const userId = req.user.id; 

    try {
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }

        if (!roles.includes(user.role)) {
            return res.status(403).json({ msg: 'Unauthorized' });
        }

        next();
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
};

// Sign in user
exports.signInUser = async (req, res) => {
    const { email, password } = req.body;

    try {
        let user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ msg: 'Invalid Credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid Credentials' });
        }

        const payload = {
            user: {
                id: user.id,
                role: user.role
            }
        };

        jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;
            
            res.json({ 
                token,
                user: {
                    name: user.name,
                    email: user.email,
                    role: user.role
                }
            });
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
};

// Enable two-factor authentication
exports.enableTwoFactorAuth = async (req, res) => {
    try {
        const userId = req.user.id;
        const secret = speakeasy.generateSecret();

        await User.findByIdAndUpdate(userId, { twoFactorSecret: secret.base32 });

        const user = await User.findById(userId);
        if (!user || !user.email) {
            return res.status(400).json({ msg: 'Missing email for label' });
        }

        const qrCodeUrl = speakeasy.otpauthURL({
            secret: secret.ascii,
            label: user.email,
            issuer: 'YourApp'
        });

        qrcode.toDataURL(qrCodeUrl, (err, data_url) => {
            if (err) {
                console.error('Error generating QR code:', err);
                return res.status(500).json({ msg: 'Error generating QR code' });
            }
            res.json({ qrCodeUrl: data_url });
        });
    } catch (err) {
        console.error('Server Error:', err.message);
        res.status(500).send('Server Error');
    }
};

// Verify two-factor authentication
exports.verifyTwoFactorAuth = async (req, res) => {
    const { token } = req.body;
    const userId = req.user.id;

    try {
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }

        if (!user.twoFactorSecret) {
            return res.status(400).json({ msg: '2FA not enabled for this user' });
        }

        const verified = speakeasy.totp.verify({
            secret: user.twoFactorSecret,
            encoding: 'base32',
            token: token
        });

        if (!verified) {
            return res.status(400).json({ msg: 'Invalid 2FA token' });
        }

        res.json({ msg: '2FA verified successfully' });
    } catch (err) {
        console.error('Server Error:', err.message);
        res.status(500).send('Server Error');
    }
};

// Get user count
exports.getUserCount = async (req, res) => {
    try {
        const count = await User.countDocuments(); 
        res.json({ count });
    } catch (error) {
        res.status(500).json({ message: 'Error retrieving user count', error });
    }
};

// Change user role
exports.changeUserRole = async (req, res) => {
    const { userId, newRole } = req.body;
    const validRoles = ['User', 'Chercheur', 'Décideurs politiques', 'Agriculteurs', 'admin'];

    if (!validRoles.includes(newRole)) {
        return res.status(400).json({ msg: 'Invalid role provided' });
    }

    try {
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }

        const oldRole = user.role;
        user.role = newRole;
        await user.save();

        logAction('changeRole', req.user.id, userId, { oldRole, newRole });

        res.json({ msg: `User role updated to ${newRole}`, user });
    } catch (err) {
        console.error('Error updating user role:', err.message);
        res.status(500).json({ msg: 'Server Error' });
    }
};

// List users with optional filters
exports.listUsers = async (req, res) => {
    const { role, status, page = 1, limit = 10 } = req.query;
    const filter = {};
    if (role) filter.role = role;
    if (status) filter.status = status;

    try {
        const totalUsers = await User.countDocuments(filter);

        const users = await User.find(filter)
            .skip((page - 1) * limit)
            .limit(Number(limit))
            .select('-password'); 

        res.json({ users, totalUsers });
    } catch (err) {
        console.error('Error listing users:', err.message);
        res.status(500).json({ msg: 'Server Error' });
    }
};

// Delete user
exports.deleteUser = async (req, res) => {
    const { userId } = req.params;

    try {
        const user = await User.findByIdAndDelete(userId);

        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }

        logAction('deleteUser', req.user.id, userId, { reason: 'User deleted by admin' });

        res.json({ msg: 'User deleted successfully' });
    } catch (err) {
        console.error('Error deleting user:', err.message);
        res.status(500).json({ msg: 'Server Error' });
    }
};

// Ban or unban user
exports.toggleBanUser = async (req, res) => {
    const { userId, ban } = req.body;

    try {
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }

        const previousStatus = user.status; 
        user.status = ban ? 'banned' : 'active';
        await user.save();

        logAction(ban ? 'banUser' : 'unbanUser', req.user.id, userId, { previousStatus, newStatus: user.status });

        res.json({ msg: `User ${ban ? 'banned' : 'unbanned'} successfully`, user });
    } catch (err) {
        console.error('Error banning/unbanning user:', err.message);
        res.status(500).json({ msg: 'Server Error' });
    }
};
exports.getAuditLogs = async (req, res) => {
    try {
      const auditLogs = await AuditLog.find()
        .populate('performedBy', 'name email')
        .populate('targetUser', 'name email')
        .sort({ timestamp: -1 });
  
      res.json({ logs: auditLogs });
    } catch (err) {
      console.error('Error fetching audit logs:', err.message);
      res.status(500).json({ msg: 'Server Error' });
    }
  };
  exports.exportAuditLogs = async (req, res) => {
    try {
      const auditLogs = await AuditLog.find()
        .populate('performedBy', 'name email')
        .populate('targetUser', 'name email')
        .sort({ timestamp: -1 });
  
      // Create CSV header with semicolon delimiter
      const csvHeader = 'Action;Performed By;Target User;Details;Timestamp\n';
  
      // Create CSV rows with semicolon delimiter
      const csvRows = auditLogs.map(log => {
        const action = log.action;
        const performedBy = log.performedBy
          ? `"${log.performedBy.name} (${log.performedBy.email})"`
          : 'N/A';
        const targetUser = log.targetUser
          ? `"${log.targetUser.name} (${log.targetUser.email})"`
          : 'N/A';
  
        // Convert details object to a readable string format and escape double quotes
        const details = JSON.stringify(log.details).replace(/"/g, '""');
  
        const timestamp = new Date(log.timestamp).toLocaleString();
  
        // Format the CSV row with semicolon delimiter
        return `${action};"${performedBy}";"${targetUser}";"${details}";${timestamp}`;
      });
  
      // Combine header and rows
      const csvContent = csvHeader + csvRows.join('\n');
  
      // Send the CSV file as a download
      res.header('Content-Type', 'text/csv');
      res.attachment('audit-logs.csv');
      res.send(csvContent);
    } catch (err) {
      console.error('Error exporting audit logs:', err.message);
      res.status(500).json({ msg: 'Server Error' });
    }
  };
  
// Get users with advanced filtering
exports.getFilteredUsers = async (req, res) => {
    const { role, status, organization, page = 1, limit = 10 } = req.query;
    const filter = {};

    if (role) filter.role = role;
    if (status) filter.status = status;
    if (organization) filter.organization = organization;

    try {
        const totalUsers = await User.countDocuments(filter);
        const users = await User.find(filter)
            .skip((page - 1) * limit)
            .limit(Number(limit))
            .select('-password'); 

        res.json({ users, totalUsers });
    } catch (err) {
        console.error('Error getting filtered users:', err.message);
        res.status(500).json({ msg: 'Server Error' });
    }
};
exports.updateUserInfo = async (req, res) => {
    const { userId, updates } = req.body; // User ID to update and updates object
    
    const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.connection.remoteAddress;
  
    try {
      let user = await User.findById(userId);
  
      if (!user) {
        return res.status(404).json({ msg: 'User not found' });
      }
  
      Object.keys(updates).forEach(key => {
        if (updates[key]) {
          user[key] = updates[key];
        }
      });
  
      await user.save();
  
      // Log the action
      await logAction('updateUserInfo', req.user.id, userId, { updates }, ipAddress);
  
      res.json({ msg: 'User information updated successfully', user });
    } catch (err) {
      console.error('Error updating user information:', err.message);
      res.status(500).json({ msg: 'Server Error' });
    }
  };
  
  