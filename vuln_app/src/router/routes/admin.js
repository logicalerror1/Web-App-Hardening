'use strict';

const multer = require('multer');
const libxmljs = require('libxmljs');
const os = require('os');
const Hoek = require('hoek');

module.exports = (app, db) => {

    // --- FIX 1: Admin Authorization Middleware ---
    // Prevents non-admins from accessing these routes
    const isAdmin = (req, res, next) => {
        // Assuming you set req.session.role in the login logic (user.js)
        // If using JWT, you might check req.decoded.role instead
        if (req.session && req.session.logged && req.session.role === 'admin') {
            return next();
        }
        return res.status(403).json({ error: "Access Denied: Admins only." });
    };

    // --- FIX 2: Secure File Upload (Whitelist) ---
    // Only allow specific image types
    const fileFilter = (req, file, cb) => {
        if (file.mimetype === 'image/jpeg' || file.mimetype === 'image/png') {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only JPG/PNG allowed.'), false);
        }
    };

    const uploadImage = multer({ 
        dest: './uploads/',
        fileFilter: fileFilter,
        limits: { fileSize: 2 * 1024 * 1024 } // Limit to 2MB
    });

    const memoryStorage = multer.memoryStorage();
    const uploadXML = multer({ 
        storage: memoryStorage,
        limits: { fileSize: 1 * 1024 * 1024 } 
    });


    // --- Route 1: Create Beer (Secured) ---
    app.post('/v1/admin/new-beer/', isAdmin, (req, res) => {
        const beerName = req.body.name;
        const beerPrice = req.body.price;
        const beerPic = req.body.picture;
        
        // Input Validation
        if(!beerName || !beerPrice) {
            return res.status(400).json({ error: "Missing fields"});
        }

        db.beer.create({
            name: beerName,
            currency: 'USD',
            stock: 'plenty',
            price: parseFloat(beerPrice), // Ensure it's a number
            picture: beerPic
        }).then(new_beer => {
            res.json(new_beer);
        }).catch(err => {
            res.status(500).json({ error: err.toString() });
        });
    });


    // --- Route 2: Upload Picture (Secured) ---
    app.post('/v1/admin/upload-pic/', isAdmin, uploadImage.single('file'), (req, res) => {
        if (!req.file) return res.status(400).send("No file uploaded or invalid type.");
        res.json(req.file);
    });


    // --- Route 3: XML Upload (Secured against XXE) ---
    app.post('/v1/admin/new-beer-xml/', isAdmin, uploadXML.single('file'), async (req, res) => {
        if (!req.file) return res.sendStatus(500);

        try {
            const xmlBuffer = req.file.buffer;
            
            // --- FIX 3: Disable External Entities (XXE Fix) ---
            // noent: false -> Disables entity expansion (Safe)
            // noent: true  -> Enables entity expansion (Vulnerable)
            const doc = libxmljs.parseXml(xmlBuffer, { 
                noent: false, // <--- CRITICAL SECURITY SETTING
                nocdata: true 
            });

            const beerName = doc.get('//name') ? doc.get('//name').text() : 'Unknown';
            const beerPrice = doc.get('//price') ? doc.get('//price').text() : '0';

            return res.json({
                parsed_name: beerName,
                parsed_price: beerPrice
            });

        } catch (err) {
            return res.status(500).json({
                error: "XML Parsing Error",
                details: "Ensure XML is valid and contains no external entities."
            });
        }
    });

};
