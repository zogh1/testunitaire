const mongoose = require('mongoose');


const AuditLogSchema = new mongoose.Schema({
    action: { type: String, required: true },
    performedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    targetUser: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Use correct field name
    details: { type: Object },
    timestamp: { type: Date, default: Date.now },
    ipAddress: { type: String }, // Ensure this field is included
  });
  
module.exports = mongoose.model('AuditLog', AuditLogSchema);
