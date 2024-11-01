// middleware/auditLogMiddleware.js

const jwt = require('jsonwebtoken');
const AuditLog = require('../models/AuditLog');

// Middleware to check if the user is authenticated
const authMiddleware = (req, res, next) => {
  const authHeader = req.header('Authorization');

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ msg: 'No token, authorization denied' });
  }

  const token = authHeader.replace('Bearer ', '');

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded.user;
    next();
  } catch (err) {
    console.error('Authentication error:', err.message);
    return res.status(401).json({ msg: 'Token is not valid' });
  }
};

// Middleware to check if the user has the 'admin' role
const isAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied. You must be an administrator to perform this action.' });
  }
  next();
};

// Function to log actions to the audit log
const logAction = async (action, performedBy, targetUserId, details, ipAddress) => {
  try {
    const auditLog = new AuditLog({
      action,
      performedBy,
      targetUser: targetUserId,
      details,
      timestamp: new Date(),
      ipAddress,
    });
    await auditLog.save();
    console.log('Audit log saved successfully.');
  } catch (error) {
    console.error('Error saving audit log:', error.message);
  }
};
module.exports = { authMiddleware, isAdmin, logAction };
