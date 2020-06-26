const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator/check');

const User = require('../models/User');

//@route        POST api/users
//@description  Register a user
//@access       Public
router.post('/', [
    check('name', 'Name is required')
        .not()
        .isEmpty(),
    check('familyName', 'Family Name is required')
        .not()
        .isEmpty(),
    check('email', 'Please include a valid email address')
        .isEmail(),
    check('password', 'Please enter a password with 8 or more characters ')
        .isLength({ min: 8 })
],
    async (req, res) => {
        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            return res.status(400).json({
                errors: errors.array()
            });
        }

        const { name, familyName, email, password } = req.body;

        try {
            let user = await User.findOne({ email: email }); // to check a user from his email
            // checking if the user exist
            if (user) {
                return res.status(400).json({ msg: "User already exist" });
            }


            // creating a new instance of the user
            user = new User({
                name,
                familyName,
                email,
                password
            });


            // crypting the password

            const salt = await bcrypt.genSalt(10);

            // console.log('salt = ', salt);

            user.password = await bcrypt.hash(password, salt);

            //  console.log('password = ', password);

            await user.save();

            const payload = { //which is the object i want to send
                user: {
                    id: user.id
                }
            };

            jwt.sign(
                payload,
                config.get('jwtSecret'),
                {
                    expiresIn: 36000
                },
                (err, token) => {
                    if (err) throw err;
                    res.json({ token });
                }
            );

        } catch (error) {
            console.error(error.message)
            res.status(500).send('Server error');
        }
    }
);

module.exports = router;

//get : is when you fetch data from the server, you're just getting data
//post : is when you're submetting something to the server
//put : is to update something which is already in the server
//delete : to delete something from the server