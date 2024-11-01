const express = require('express');
const router = express.Router();
const biomassController = require('../controllers/ExcelController');
const { getBiomassData,getBiomassCount,getDistinctBiomassTypesCount} = require('../controllers/BiomasSourceController');
const { authMiddleware, isAdmin } = require('../middleware/auditLogMiddleware');
const BiomasSourceController = require('../controllers/BiomasSourceController');

// Route to upload files, requires authentication and admin role
router.post('/upload', authMiddleware, isAdmin, biomassController.uploadMiddleware, biomassController.uploadFile);

// Route to get all biomass data
router.get('/biomass', getBiomassData);
router.get('/api/biomass/types-by-location', BiomasSourceController.getBiomassTypesByLocation);
router.get('/count', getBiomassCount); // Add this line to handle the count request
router.get('/api/biomass/distinct-types-count', getDistinctBiomassTypesCount);



module.exports = router;
