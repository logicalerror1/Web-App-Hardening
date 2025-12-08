'use strict';

const multer = require('multer');
const libxmljs = require('libxmljs');
const os = require('os');
const Hoek = require('hoek');

module.exports = (app, db) => {

    
    app.post('/v1/admin/new-beer/', (req, res) => {
        const beerName = req.body.name;
        const beerPrice = req.body.price;
        const beerPic = req.body.picture;
        const beerCurrncy = 'USD';
        const beerStock = 'plenty';

        db.beer.create({
            name: beerName,
            currency: beerCurrncy,
            stock: beerStock,
            price: beerPrice,
            picture: beerPic
        }).then(new_beer => {
            res.json(new_beer);
        }).catch(err => {
            res.status(500).json({ error: err.toString() });
        });
    });

    
    const uploadImage = multer({ dest: './uploads/' });

    app.post('/v1/admin/upload-pic/', uploadImage.single('file'), (req, res) => {
        if (!req.file) return res.sendStatus(500);

        res.json(req.file);
    });


    const memoryStorage = multer.memoryStorage();
    const uploadXML = multer({ storage: memoryStorage });

    app.post('/v1/admin/new-beer-xml/', uploadXML.single('file'), async (req, res) => {

        if (!req.file) return res.sendStatus(500);

        try {
            const xmlBuffer = req.file.buffer;
            const doc = libxmljs.parseXml(xmlBuffer, { noent: true });

           
            const beerName = doc.get('//name').text();
            const beerPrice = doc.get('//price').text();

          
            return res.json({
                parsed_name: beerName,
                parsed_price: beerPrice
            });

        } catch (err) {
            return res.status(500).json({
                error: err.toString(),
                message: "XML parse failed (maybe malformed or XXE error)."
            });
        }
    });

};
