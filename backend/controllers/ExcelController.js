const multer = require('multer');
const path = require('path');
const xlsx = require('xlsx');
const Biomass = require('../models/Biomass'); // Adjust the path as needed

// Configure multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}_${file.originalname}`);
  }
});

const uploadMiddleware = multer({ storage }).single('file');

const uploadFile = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ msg: 'No file uploaded' });
    }

    // File path
    const filePath = path.join(__dirname, '..', 'uploads', req.file.filename);

    // Read the Excel file
    const workbook = xlsx.readFile(filePath);
    const sheetNames = workbook.SheetNames;
    const data = sheetNames.flatMap(sheetName => xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]));


    // Process the data (e.g., save to database)
    await Biomass.insertMany(data);

    res.status(200).json({ msg: 'File uploaded and processed successfully' });

  } catch (err) {
    console.error('Error uploading or processing file:', err.message);
    res.status(500).json({ msg: 'Server Error' });
  }
};

module.exports = {
  uploadMiddleware,
  uploadFile
};
