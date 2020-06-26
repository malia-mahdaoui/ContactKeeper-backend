//the middlware is just a fonction that has access to the request and the response object

const jwt = require('jsonwebtoken');
const config = require('config');


module.exports = function (req, res, next) {
    //Get token from header


    //If there's a token wwe need to verify it
    try {

        const token = req.header('x-auth-token'); //The key  to the token inside the header

        //Check if not token
        if (!token) {
            return res.status(401).json({ msg: "No token authorization denied" });
        }
        const decoded = jwt.verify(token, config.get('jwtSecret'));

        //Once it's got verified 
        //decoded contains the entire 

        req.user = decoded.user;
        next();

    } catch (error) {

        //If it's not valid

        res.status(401).json({ msg: "Token is not valid" });

    }
}