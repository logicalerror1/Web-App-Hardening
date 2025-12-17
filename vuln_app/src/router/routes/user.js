'use strict';

require('dotenv').config();
const jwt = require("jsonwebtoken");
const bcrypt = require('bcrypt');
const otplib = require('otplib');
const validator = require('validator'); // Prefer validator library over regex
const config = require('./../../config');

module.exports = (app, db) => {

    // --- HELPER: Secure JWT Middleware ---
    const verifyToken = (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.status(401).json({ error: "Missing Token" });

        const token = authHeader.split(' ')[1];
        if (!token) return res.status(401).json({ error: "Invalid Token Format" });

        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) return res.status(403).json({ error: "Invalid or Expired Token" });
            req.decoded = decoded; // Store secure payload
            next();
        });
    };

    // --- HELPER: Admin Check ---
    const isAdmin = (req, res, next) => {
        if (req.decoded && req.decoded.role === 'admin') {
            next();
        } else {
            res.status(403).json({ error: "Access Denied: Admins Only" });
        }
    };


    // --- 1. Fix Authorization Bypass (Get All Users) ---
    app.get('/v1/admin/users/', verifyToken, isAdmin, (req, res) => {
        // Now secure: Only verified admins reach here
        db.user.findAll({ include: "beers" })
            .then(users => res.json(users))
            .catch(e => res.status(500).json({ error: "Database error" }));
    });


    // --- 2. Fix IDOR (Get Specific User) ---
    app.get('/v1/user/:id', verifyToken, (req, res) => {
        // Allow if Admin OR if requesting own ID
        if (req.decoded.id != req.params.id && req.decoded.role !== 'admin') {
            return res.status(403).json({ error: "Access Denied" });
        }

        db.user.findOne({ include: 'beers', where: { id: req.params.id } })
            .then(user => {
                if (!user) return res.status(404).json({ error: "User not found" });
                // Don't send password hash back
                const safeUser = user.toJSON();
                delete safeUser.password;
                res.json(safeUser);
            });
    });


    // --- 3. Fix Broken Function Level Auth (Delete User) ---
    app.delete('/v1/user/:id', verifyToken, isAdmin, (req, res) => {
        // Only admins can delete users
        db.user.destroy({ where: { id: req.params.id } })
            .then(() => res.json({ result: "deleted" }))
            .catch(e => res.status(500).json({ error: e }));
    });


    // --- 4. Fix ReDoS & Weak Password (Create User) ---
    app.post('/v1/user/', (req, res) => {
        const { email, name, password, address } = req.body;
        // Role is forced to 'user' to prevent Privilege Escalation
        const role = 'user';

        // FIX: Use validator lib (Safe from ReDoS)
        if (!validator.isEmail(email)) {
            return res.status(400).json({ error: "Invalid email format" });
        }

        // FIX: Secure Password Hashing
        const hashedPassword = bcrypt.hashSync(password, 10);

        db.user.create({
            name,
            email,
            role,
            address,
            password: hashedPassword
        }).then(new_user => res.json(new_user))
          .catch(e => res.status(500).json({ error: "Creation failed" }));
    });


    // --- 5. Fix CSRF (Get/Post Love Beer) ---
    // NOTE: In a real API, 'GET' should not modify state. 
    // This route should ideally be removed, but we secure it with Auth checks.
    app.get('/v1/love/:beer_id', verifyToken, (req, res) => {
        const userId = req.decoded.id; // Take from trusted Token, NOT query param
        const beerId = req.params.beer_id;

        db.beer.findByPk(beerId).then(beer => {
            if (!beer) return res.status(404).json({ error: "Beer not found" });

            db.user.findByPk(userId).then(user => {
                if (!user) return res.status(404).json({ error: "User not found" });

                user.hasBeer(beer).then(alreadyLoved => {
                    if (!alreadyLoved) {
                        user.addBeer(beer, { through: 'user_beers' });
                    }
                    if (req.query.front) {
                        return res.redirect(`/beer?id=${beerId}&user=${userId}&message=Loved!`);
                    }
                    res.json({ message: "Beer loved successfully" });
                });
            });
        });
    });


    // --- 6. Fix Insecure JWT Implementation (Login Token) ---
    app.post('/v1/user/token', (req, res) => {
        const { email, password } = req.body;

        db.user.findOne({ where: { email } }).then(user => {
            if (!user) return res.status(404).json({ error: 'User not found' });

            // FIX: Compare with Bcrypt
            if (bcrypt.compareSync(password, user.password)) {
                // FIX: Use Strong Secret & Algorithm
                const token = jwt.sign(
                    { id: user.id, role: user.role },
                    process.env.JWT_SECRET,
                    { expiresIn: '1h', algorithm: 'HS256' }
                );
                res.status(200).json({ jwt: token, user: user });
            } else {
                res.status(401).json({ error: 'Invalid credentials' });
            }
        });
    });


    // --- 7. Fix Mass Assignment (Update User) ---
    app.put('/v1/user/:id', verifyToken, (req, res) => {
        // Users can only update their own profile
        if (req.decoded.id != req.params.id) {
            return res.status(403).json({ error: "Access Denied" });
        }

        // FIX: Whitelist only safe fields (No 'role', No 'password')
        const safeUpdates = {
            email: req.body.email,
            profile_pic: req.body.profile_pic,
            address: req.body.address,
            name: req.body.name
        };

        db.user.update(safeUpdates, { where: { id: req.params.id } })
            .then(() => res.json({ message: "Profile Updated" }))
            .catch(e => res.status(500).json({ error: "Update failed" }));
    });


    // --- 8. Fix Privilege Escalation (Promote Admin) ---
    app.put('/v1/admin/promote/:id', verifyToken, isAdmin, (req, res) => {
        // Secure: Only real admins can reach here via middleware
        db.user.update({ role: 'admin' }, { where: { id: req.params.id } })
            .then(() => res.json({ message: "User promoted to Admin" }));
    });


    // --- 9. Fix Broken 2FA (Validate OTP) ---
    app.post('/v1/user/:id/validate-otp', verifyToken, (req, res) => {
        // Do not accept seed from query (Client Side). Seed must be secret on server.
        // For this fix, we assume the seed is stored in DB or Env.
        const serverSeed = process.env.OTP_SEED || 'SERVER_SIDE_SECRET_SEED'; 
        const userToken = req.body.token; // Pass token in Body, not URL

        // Validate
        const isValid = otplib.authenticator.check(userToken, serverSeed);

        if (isValid) {
            // Issue JWT
            const token = jwt.sign(
                { id: req.decoded.id, role: req.decoded.role, mfa: true },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );
            res.json({ jwt: token, message: "MFA Validated" });
        } else {
            res.status(401).json({ error: "Invalid OTP Code" });
        }
    });

};
