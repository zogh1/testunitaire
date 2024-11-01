const Biomass = require('../models/Biomass');

const getBiomassData = async (req, res) => {
    try {
      const biomassData = await Biomass.find({}).lean();
      res.json(biomassData);
    } catch (err) {
      console.error('Erreur lors de la récupération des données de biomasse:', err.message);
      res.status(500).json({ msg: 'Erreur lors de la récupération des données de biomasse' });
    }
  };
  
  // New function to get biomass types by location
  const getBiomassTypesByLocation = async (req, res) => {
    const { location } = req.query;
  
    if (!location) {
      return res.status(400).json({ msg: 'Location is required' });
    }
  
    try {
      // Fetch the biomass data based on the location
      const biomassData = await Biomass.find(
        { Localisation: location },  // Filtering by location
        {
          "Type de Biomasse": 1,  // Explicitly specifying the fields you want
          "Type Précis de Biomasse": 1,
          "Quantité de Biomasse (tonnes)": 1,
          "Disponibilité Saisonnière": 1
        }
      ).lean();
  
      res.json(biomassData);
    } catch (err) {
      console.error('Error fetching biomass data:', err.message);
      res.status(500).json({ msg: 'Error fetching biomass data' });
    }
};
const getBiomassCount = async (req, res) => {
  try {
    const count = await Biomass.countDocuments(); // Count all biomass documents
    res.json({ count });
  } catch (err) {
    console.error('Erreur lors de la comptabilisation des données de biomasse:', err.message);
    res.status(500).json({ msg: 'Erreur lors de la comptabilisation des données de biomasse' });
  }
};
getDistinctBiomassTypesCount = async (req, res) => {
  try {

    const distinctTypes = await Biomass.distinct("Type de Biomasse");
    const count = distinctTypes.length; // Get the count of unique types
    res.json({ count }); // Send the count as a response
  } catch (error) {
    console.error('Error fetching distinct biomass types:', error.message);
    res.status(500).json({ msg: 'Error fetching distinct biomass types' });
  }
};

module.exports = {
  getBiomassData,
  getBiomassTypesByLocation,
  getBiomassCount,
  getDistinctBiomassTypesCount,
};
