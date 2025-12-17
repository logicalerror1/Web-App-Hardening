'use strict';

const escapeHtml = require('escape-html'); // Ensure you have: npm install escape-html

module.exports = (app, db) => {

    // --- 1. Fix RCE (Remote Code Execution) ---
    /**
     * GET /v1/status/{brand}
     * @summary Check status safely (Fixed)
     */
    app.get('/v1/status/:brand', (req, res) => {
        // FIX: Removed 'child_process'. 
        // We now just return a string. No shell commands are executed.
        const brand = req.params.brand;
        
        // Escape the input just in case to prevent XSS in the response
        res.send(`Status for ${escapeHtml(brand)}: Service is reachable.`);
    });

    // --- 2. Fix Insecure Redirect ---
    /**
     * GET /v1/redirect/
     * @summary Safe Redirect (Fixed)
     */
    app.get('/v1/redirect/', (req, res) => {
        const url = req.query.url;
        console.log("Redirect requested to:", url);

        if (url) {
            // FIX: Only allow Relative Paths (starts with / but not //)
            // This prevents redirecting to https://evil.com
            if (url.startsWith('/') && !url.startsWith('//')) {
                return res.redirect(url);
            } 
            
            // Optional: Allow specific whitelisted domains
            // if (url === 'https://google.com') return res.redirect(url);

            return res.status(400).send("External redirects are forbidden.");
        } else {
            res.status(404).send("No URL provided");
        }
    });

    // --- 3. Fix Insecure Object Deserialization ---
    /**
     * POST /v1/init/
     * @summary Initialize safely using JSON (Fixed)
     */
    app.post('/v1/init', (req, res) => {
        // FIX: Removed 'node-serialize'. 
        // JSON.parse is safe because it only parses data, it cannot execute functions.
        try {
            const body = req.body.object;
            
            // Assuming input is a JSON string. 
            // If body-parser is already used, 'req.body.object' might already be an object.
            // We ensure we handle it safely.
            let data;
            if (typeof body === 'string') {
                data = JSON.parse(body);
            } else {
                data = body;
            }

            console.log("Safe data received:", data);
            res.send("Initialization successful (Safe Mode)");
        } catch (e) {
            res.status(400).send("Invalid JSON format");
        }
    });

    // --- 4. Fix SSRF (Server Side Request Forgery) ---
    /**
     * GET /v1/test/
     * @summary Perform safe HTTP requests (Fixed)
     */
    app.get('/v1/test/', (req, res) => {
        const axios = require('axios');
        const url = req.query.url;

        if (!url) {
            return res.json({ error: "No url provided" });
        }

        // FIX: Implement a Whitelist. 
        // Only allow requests to specific, trusted domains.
        // Block all internal IPs (localhost, 127.0.0.1, 192.168.x.x)
        const allowedDomains = ['google.com', 'example.com', 'wikipedia.org'];

        try {
            const parsedUrl = new URL(url);
            
            if (!allowedDomains.includes(parsedUrl.hostname)) {
                return res.status(403).json({ 
                    error: "SSRF Protection: This domain is not in the whitelist." 
                });
            }

            // If domain is safe, proceed
            axios.get(url, { validateStatus: () => true })
                .then(response => {
                    res.json({
                        status: response.status,
                        // Don't return headers/data blindly in production, but okay for this test
                        data: "Request successful to whitelisted domain."
                    });
                })
                .catch(error => {
                    res.json({ error: "Request failed" });
                });

        } catch (err) {
            return res.status(400).json({ error: "Invalid URL" });
        }
    });
};
