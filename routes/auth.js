/* auth will have two 2 routes, one to get the login 
and user and one to actually login the user and get 
the token*/


const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const config = require('config');
const jwt = require('jsonwebtoken');
const auth = require('../middleware/auth');
const { check, validationResult } = require('express-validator/check');


const User = require('../models/User');

//@route        GET api/auth
//@description  Get logged in user
//@access       Private cause we're getting a user that is logged in so obviously it's private
// I want it to be a protective route
router.get('/', auth,

    async (req, res) => {
        // res.send('Get logged in user');
        try {
            const user = await User.findById(req.user.id).select('-password');
            res.json(user);

        } catch (error) {
            console.error(error.message);
            res.status(500).send('Server Error 500');
        }
    });



//@route        POST api/auth
//@description  Auth user and get token, cause we're sending data to get authentificated
//@access       Public
router.post('/',
    [
        check('email', 'Please include a valid email').isEmail(),
        check('password', 'Password is required').exists()
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;

        try {

            let user = await User.findOne({ email });

            if (!user) {
                return res.status(400).json({ msg: 'Invalid Credentials email' });
            }

            const isMatch = await bcrypt.compare(password, user.password);


            if (!isMatch) {
                return res.status(400).json({ msg: 'Invalid Credentials password' });
            }

            const payload = {
                user: {
                    id: user.id
                }
            };

            jwt.sign(
                payload,
                config.get('jwtSecret'),
                {
                    expiresIn: 360000
                },
                (err, token) => {
                    if (err) throw err;
                    res.json({ token });
                }
            );

        } catch (error) {
            console.error(err.message);
            res.status(500).send('Server Error');
        }
    }
);



module.exports = router;

//get : is when you fetch data from the server, you're just getting data
//post : is when you're submetting something to the server
//put : is to update something which is already in the server
//delete : to delete something from the server