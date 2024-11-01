const mongoose = require('mongoose');

const BiomassSchema = new mongoose.Schema({}, { strict: false });  

module.exports = mongoose.model('Biomass', BiomassSchema);
