const User = require('../models/User');
const { StatusCodes } = require('http-status-codes');
const { BadRequestError, UnauthenticatedError } = require('../errors');
// const bcrypt = require('bcryptjs');         // bcryptjs for hashing password to store in the database 
// const jwt = require('jsonwebtoken');        // packge to use javascript web token 

const register = async ( req, res) => {
    // const { name, email, password } = req.body;

    // const salt = await bcrypt.genSalt(10);      //generate random 10 bytes
    // const hashedPassword = await bcrypt.hash(password, salt);       //hash the password using salt generated

    // const tempUser = {name, email, password: hashedPassword};       //store the hashed password in the database
    // const user = await User.create({...tempUser});

    const user = await User.create({...req.body});

    // jwt.sign(payload, secret key, Options)
    // payload is the data to be transferred
    // const token = jwt.sign({ userId: user._id, name: user.name }, 'jwtSecret', {expiresIn: '30d'});
    
    const token = user.createJWT();     //use the defined fuction of user to create the JWT token
    res.status(StatusCodes.CREATED).json({ user: user.name, token});
}

const login = async ( req, res) => {
    const { email, password } = req.body;
    
    if(!email || !password) {
        throw new BadRequestError ('Please provide email and password!!');
    }

    const user = await User.findOne({email});
    if (!user) {
        throw new UnauthenticatedError ('User does not exist');
    }

    const isPasswordCorrect = await user.comparePassword(password);
    if (!isPasswordCorrect) {
        throw new UnauthenticatedError ('User does not exist');
    }

    const token = user.createJWT();
    res.status(StatusCodes.OK).json({ user: {name: user.name}, token})

}

module.exports = {register, login};