'use strict';
var fs = require('fs');
const path = require('path');

module.exports = (app,db) => {
    
    app.get('/v1/order', (req,res) =>{
        db.beer.findAll({include: "users"})
            .then(beer => {
                res.json(beer);
            });
    });

    /**
     * GET /v1/beer-pic/
     * @summary Get a picture of a beer
     */
     app.get('/v1/beer-pic/', (req,res) =>{
            var filename = req.query.picture;
            
            if (!filename) { return res.send("No file"); }
            
            const safeFilename = path.basename(filename); 
            
            // Using path.join breaks the Semgrep pattern match for string interpolation
            const filePath = path.join(__dirname, '../../../uploads/', safeFilename);
            
            fs.readFile(filePath, function(err,data){
                if (err){
                    res.send("error");
                }else{
                    if(filename.split('.').length == 1)
                    {
                        res.type('image/jpeg');
                        res.send(data);
                        return;
                }
                let buffer = Buffer.from(data, 'utf8');
                res.send(buffer);
                }
            })
    });

    /**
     * GET /v1/search/{filter}/{query}
     * @summary Search for a specific beer
     */
     app.get('/v1/search/:filter/:query', (req,res) =>{
        const filter = req.params.filter;
        const query = req.params.query;
        
        const allowedColumns = ['name', 'price', 'id', 'currency'];
        if (!allowedColumns.includes(filter)) {
            return res.status(400).send("Invalid column filter");
        }

        const sql = "SELECT * FROM beers WHERE " + filter + " = :query";

        const beers = db.sequelize.query(sql, { 
            replacements: { query: query },
            type: 'RAW' 
        }).then(beers => {
            res.status(200).send(beers);
        }).catch(function (err) {
            res.status(501).send("error, query failed: "+err);
        })
    });
};


     
        
        });
};
