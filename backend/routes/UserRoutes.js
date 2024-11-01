const express = require('express');
const router = express.Router();

const userController = require('../controllers/UserController');
const { authMiddleware, isAdmin } = require('../middleware/auditLogMiddleware');
const validationMiddleware = require('../middleware/validationMiddleware');

// Middleware to log all incoming requests for debugging
router.use((req, res, next) => {
  console.log(`Incoming request: ${req.method} ${req.url}`);
  next();
});

// User management routes
router.put('/change-role', authMiddleware, isAdmin, userController.changeUserRole);
router.put('/ban-user', authMiddleware, isAdmin, userController.toggleBanUser);
router.get('/list-users', authMiddleware, isAdmin, userController.listUsers);
router.delete('/delete-user/:userId', authMiddleware, isAdmin, userController.deleteUser);
router.put('/update-user-info', authMiddleware, isAdmin, userController.updateUserInfo);

// Authentication and registration routes
router.post('/signin-sogo', userController.signInWithSOGo);
router.post('/register-sogo', userController.registerWithSogo);
router.post('/register', validationMiddleware.validateRegister, userController.registerUser);
router.get('/verify/:token', userController.verifyEmail);
router.post('/check-email', userController.checkEmail);
router.post('/forgot-password', userController.forgotPassword);
router.post('/reset-password/:token', validationMiddleware.validateResetPassword, userController.resetPassword);
router.get('/profile', authMiddleware, userController.getUserProfile);
router.put('/profile', authMiddleware, userController.updateUserProfile);
router.post('/signin', validationMiddleware.validateSignIn, userController.signInUser);
router.post('/enable-2fa', authMiddleware, userController.enableTwoFactorAuth);
router.post('/verify-2fa', authMiddleware, userController.verifyTwoFactorAuth);
router.get('/count', userController.getUserCount);


router.get('/audit-logs', authMiddleware, isAdmin, userController.getAuditLogs);

// Endpoint to export audit logs to CSV
router.get('/audit-logs/export', authMiddleware, isAdmin, userController.exportAuditLogs);
// New route for advanced filtering of users
router.get('/filtered-users', authMiddleware, isAdmin, userController.getFilteredUsers);

module.exports = router;
