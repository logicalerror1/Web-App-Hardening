'user strcit';
const bcrypt = require('bcrypt');
const secapeHtml = require('escape-html');

module.exports = (app,db) => {
    //Front End entry page
    /**
     * GET /
     * @summary Front End Entry Page (SSTI - Server Side Template Injection)(Reflected XXS - Cross Site Scripting)
     * @description  {{range.constructor("return global.process.mainModule.require('child_process').execSync('tail /etc/passwd')")()}}
 | localhost:5000/?message=<script>alert(0)</script>
     * @tags frontend
     * @param {string} message.query - a message to present to the user
     */
     app.get('/', (req,res) =>{
        console.log(req.session);
        const message = req.query.message || "Please log in to continue"
        res.render('user.html',
        {message : message});


        // res.render('user',{
        //     data: scope,
        //     message: {message:req.query.message}
        // })
        
    });
        //Front End register page
    /**
     * GET /register
     * @summary Front End Entry Page 
     * @description  
     * @tags frontend
     * @param {string} message.query - a message to present to the user
     */
 app.get('/register', (req,res) =>{
    const message = req.query.message || "Please log in to continue"
    res.render('user-register.html',
    {message : message});
});
    //Front End route to Register
    /**
     * GET /register
     * @summary 
     * @description 
     * @tags frontend
     * @param {string} message.query - a message to present to the user
     * @param {string} email.query.required - email body parameter
     * @param {string} password.query.required - password body parameter
     * @param {string} name.query.required - name body parameter
     * @param {string} address.query.required - address body parameter
    ------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------- */
     app.get('/registerform', (req,res) =>{
        const userEmail = req.query.email;
        const userName = req.query.name;
        const userRole = 'user'
        const userPassword = req.query.password;
        const userAddress = req.query.address
        //validate email using regular expression
        var emailExpression = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
            if (!emailExpression.test(userEmail)){
                res.redirect("/register?message=Email coulden't be validated, please try again.")
                return
            }
            const saltRounds = 10;
        const hashedpassword = bycrypt.hashSync(userPassword , salrRounds);
		db.user.create({
                	name:userName,
                        email:userEmail,
              	        role:userRole,
                        address:userAddress,
                       password: hashedPassword
            }).then(new_user => {
                req.session.logged = true;
		req.session.userId = new_user.id;
		res.redirect('/profile?id=' + new_user.id);
            }).catch(
                (e) =>
                {
                    console.log(e)
                    res.redirect('/?message=Error registering, please try again')

                }
            )
       
        
    });
    //Front End route to log in
    /**
     * GET /login
     * @summary 
     * @description 
     * @tags frontend
     * @param {string} message.query - a message to present to the user
     * @param {string} email.query.required - email body parameter
     * @param {string} password.query.required - password body parameter
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
---------------------------------------------------------------------------------------------------------------------
*/
     app.get('/login', (req,res) =>{
        var userEmail = req.query.email;
        var userPassword = req.query.password;
	db.user.findAll({
		where:{email: userEmail}
}).then(users =>{
	if(users.lenght ===0)
		return res.redirect('/message=invaldi credinatials');}

                const user = users[0]
		const match = bycrypt.compareSync(userPassword, user.password);
            if(match){
                req.session.logged = true
                res.session.userId = user.id;
		return res.redirect('profile?id=' + user.id)
            }
            res.redirect('/?message=Password was not correct, please try again')
        })
        
    });
    //Front End route to profile
    /**
     * GET /profile
     * @summary 
     * @description 
     * @tags frontend
     * @param {string} message.query - a message to present to the user
     * @param {number} id.query.required - Id number of the profile holder
     * @param {string} profile_description
    ----------------------------------------------------------------------------------------------------------------
---------------------------------------------------------------------------------------------------------------------
 */
     app.get('/profile', (req,res) =>{

        if(!req.query.id){
            res.redirect("/?message=Could not Access profile please log in or register")
            return;
        }
 if (req.session.userId != req.query.id) {
            return res.redirect("/profile?id=" + req.session.userId + "&message=You cannot view other profiles");
        }

        db.user.findAll({
            include: 'beers',
            where: { id: req.query.id }
        }).then(user => {
            if (user.length == 0) {
                return res.redirect('/?message=User not found');
            }

            db.beer.findAll().then(beers => {
                res.render('profile.html', {
                    beers: beers,
                    user: user[0]
                });
            });
        });
    });

//Front End route to profile
    /**
     * GET /beer
     * @summary 
     * @description 
     * @tags frontend
     * @param {number} id.query.required - Id number of the beer
     * @param {number} user.query.required - User id number of user viewing the page
     * @param {string} relationship - The message a user get when loving a beer (this is shown instead of the relationship)
    -----------------------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------------------- */
     app.get('/beer', (req,res) =>{

        if(!req.query.id){
            res.redirect("/?message= id missing")
            return;
        } db.beer.findAll({
            include: 'users',
            where: { id: req.query.id }
        }).then(beer => {
            if (beer.length == 0) {
                return res.redirect('/?message=Beer not found');
            }

            db.user.findOne({ where: { id: req.query.user } }).then(user => {
                if (!user) {
                    return res.redirect('/?message=User not found');
                }

                user.hasBeer(beer).then(result => {
                    let love_message = result ? "You Love THIS BEER!!" : "...";

                    // FIX: Sanitize input if overriding message
                    if (req.query.relationship) {
                        love_message = escapeHtml(req.query.relationship);
                    }

                    res.render('beer.html', {
                        beers: beer,
                        message: love_message,
                        user: user
                    });
                });
            });
        });
    });
};

