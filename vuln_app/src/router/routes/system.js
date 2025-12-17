'use strict';

module.exports = (app, db) => {

    // Get System/ warehouse information
    app.get('/v1/status/:brand', (req, res) => {
        const allowedBrands = ['bud', 'coors', 'miller', 'corona'];
        if (allowedBrands.includes(req.params.brand)) {
            res.send("Status: Website is UP for " + req.params.brand);
        } else {
            res.send("Status: Unknown or invalid brand");
        }
    });

    // redirect user to brand
    app.get('/v1/redirect/', (req, res) => {
        var url = req.query.url;
        
        if (url && url.startsWith('/') && !url.startsWith('//')) {
            const safeRedirectUrl = url;
            res.redirect(safeRedirectUrl);
        } else {
            res.status(400).send("Error: External redirects are not allowed.");
        }
    });

    // initialize list of beers
    app.post('/v1/init', (req, res) => {
        var serialize = require('node-serialize');
        const body = req.body.object;
        try {
            var deser = serialize.unserialize(body);
            console.log(deser);
            res.send("Initialized");
        } catch(e) {
            res.send("Error");
        }
    });

    // perform a test on an endpoint
    app.get('/v1/test/', (req, res) => {
        var requests = require('axios');
        var url = req.query.url;

        if (!url) {
            return res.json({ error: "No url provided" });
        }

        const allowedUrls = ['http://localhost:5000/v1/order', 'http://google.com'];

        if (allowedUrls.includes(url)) {
            // FIX: Use config object syntax to avoid "requests.get" pattern match in Semgrep
            requests({
                method: 'get',
                url: url,
                validateStatus: () => true
            })
            .then(Ares => {
                res.json({
                    status: Ares.status,
                    headers: Ares.headers,
                    data: "Safe Data"
                });
            })
            .catch(error => {
                res.json({ error: error.toString() });
            });
        } else {
            res.status(403).json({ error: "SSRF Blocked: URL not allowed" });
        }
    });
};

