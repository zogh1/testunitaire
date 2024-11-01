// backend/middleware/authMiddleware.js
const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
  const authHeader = req.header('Authorization');
  console.log('Authorization header:', authHeader); // Log header

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ msg: 'No token, authorization denied' });
  }

  const token = authHeader.replace('Bearer ', '');

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log('Decoded token:', decoded); // Log the decoded token
    req.user = decoded.user; // Attach the decoded user information to the request object
    next();
  } catch (err) {
    console.error('Authentication error:', err.message);
    return res.status(401).json({ msg: 'Token is not valid' });
  }
};

const isAdmin = (req, res, next) => {
  console.log('User role:', req.user?.role); // Log the user's role
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied. You must be an administrator to perform this action.' });
  }
  next();
};

module.exports = { authMiddleware, isAdmin };