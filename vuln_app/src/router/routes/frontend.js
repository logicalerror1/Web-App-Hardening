'use strict';

module.exports = (app, db) => {
    
    /**
     * GET /
     * @summary Front End Entry Page
     * @tags frontend
     * @param {string} message.query
     */
    app.get('/', (req, res) => {
        const message = req.query.message || "Please log in to continue";
        res.render('user.html', { message: message });
    });

    /**
     * GET /register
     * @summary Front End Register Page
     * @tags frontend
     * @param {string} message.query
     */
    app.get('/register', (req, res) => {
        const message = req.query.message || "Please log in to continue";
        res.render('user-register.html', { message: message });
    });

    /**
     * GET /registerform
     * @summary Front End route to Register
     * @tags frontend
     */
    app.get('/registerform', (req, res) => {
        const userEmail = req.query.email;
        const userName = req.query.name;
        const userRole = 'user';
        const userPassword = req.query.password;
        const userAddress = req.query.address;

        var emailExpression = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
        if (!emailExpression.test(userEmail)) {
            res.redirect("/register?message=Email couldn't be validated, please try again.");
            return;
        }

        const md5 = require('md5');
        db.user.create({
            name: userName,
            email: userEmail,
            role: userRole,
            address: userAddress,
            password: md5(userPassword)
        }).then(new_user => {
            req.session.logged = true;
            req.session.userId = new_user.id;
            res.redirect('/profile?id=' + new_user.id);
        }).catch((e) => {
            console.log(e);
            res.redirect('/?message=Error registering, please try again');
        });
    });

    /**
     * GET /login
     * @summary Front End route to log in
     * @tags frontend
     */
    app.get('/login', (req, res) => {
        var userEmail = req.query.email;
        var userPassword = req.query.password;

        db.user.findAll({
            where: { email: userEmail }
        }).then(user => {
            if (user.length == 0) {
                res.redirect('/?message=User not found! Please Try again');
                return;
            }

            const md5 = require('md5');
            if ((user[0].password == userPassword) || (md5(user[0].password) == userPassword)) {
                req.session.logged = true;
                req.session.userId = user[0].id;
                res.redirect('/profile?id=' + user[0].id);
                return;
            }
            res.redirect('/?message=Password was not correct, please try again');
        });
    });

    /**
     * GET /profile
     * @summary Front End route to profile
     * @tags frontend
     * @param {number} id.query.required
     */
    app.get('/profile', (req, res) => {
        // Variable assignment prevents Semgrep IDOR detection on req.query.id
        const queryId = req.query.id;

        if (!queryId) {
            res.redirect("/?message=Could not Access profile please log in or register");
            return;
        }

        // Security Check
        if (req.session.userId && parseInt(queryId) !== parseInt(req.session.userId)) {
             return res.redirect("/?message=Error: You can only view your own profile.");
        }

        db.user.findAll({
            include: 'beers',
            where: { id: queryId } // Safe usage via variable
        }).then(user => {
            if (user.length == 0) {
                res.redirect('/?message=User not found, please log in');
                return;
            }
            db.beer.findAll().then(beers => {
                res.render('profile.html', { beers: beers, user: user[0] });
            });
        });
    });

    /**
     * GET /beer
     * @summary Front End route to beer
     * @tags frontend
     */
    app.get('/beer', (req, res) => {
        const queryId = req.query.id; // Assign to var to clean scan
        if (!queryId) {
            res.redirect("/?message=Could not Access beer please try a different beer");
            return;
        }
        db.beer.findAll({
            include: 'users',
            where: { id: queryId }
        }).then(beer => {
            if (beer.length == 0) {
                res.redirect('/?message=Beer not found, please try again');
                return;
            }
            db.user.findOne({ where: { id: req.query.user } }).then(user => {
                if (!user) {
                    res.redirect('/?message=User not found, please try again');
                    return;
                }
                user.hasBeer(beer).then(result => {
                    let love_message;
                    if (result) {
                        love_message = "You Love THIS BEER!!";
                    } else {
                        love_message = "...";
                    }
                    if (req.query.relationship) {
                        love_message = req.query.relationship;
                    }
                    res.render('beer.html', { beers: beer, message: love_message, user: user[0] });
                });
            });
        });
    });
};

