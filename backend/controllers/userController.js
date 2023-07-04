const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const asyncHandler = require('express-async-handler');
const User = require('../models/userModel');
// @desc        Register new user
// @route       POST /api/users
// @access      Public
const registerUser = asyncHandler( async (req,res) =>{
    
    const {name, email, password} = req.body;

    console.log(req.body)
    console.log(`${name} ${email} ${password}`);
    if(!name || !email || !password){
        res.status(400);
        throw new Error('Please add all fields');
    }
    //check if user exists
    const userExists = await User.findOne({email});

    if(userExists){
        res.status(400);
        throw new Error('User already exists');
    }

    //hash password
    const salt = await bcrypt.genSalt(10);

    const hashedPassword = await bcrypt.hash(password,salt);
    
    //create user
    const user = await User.create({
        name,
        email,
        password: hashedPassword
    });

    if(user){
        res.status(201).json({
        _id: user.id,
        name: user.name,
        email: user.email,
        token: GenerateToken(user._id)
        })
    } 
    else{
        res.status(400);
        throw new Error('Invalid user data');
    }

    res.json({message: 'register user'});
})

// @desc        Authenticate a user
// @route       POST /api/users/login
// @access      Private
const loginUser = asyncHandler(async (req,res) =>{
    const {email, password} = req.body;

    //check for user email
    const user = await User.findOne({email});

    if(user && (await bcrypt.compare(password,user.password))){
        res.json({
            _id: user.id,
            name: user.name,
            email: user.email,
            token: GenerateToken(user._id)
        });
    }
    else{
        res.status(400);
        throw new Error('Invalid credentials');
    }

    res.json({message: 'login user'});
})

// @desc        Get user data 
// @route       GET /api/users/me
// @access      Private
const getMe = asyncHandler(async (req,res) =>{



    res.status(200).json(req.user);
});

//Generate JWT
const GenerateToken = (id) =>{
    return jwt.sign({id}, process.env.JWT_SECRET, {
        expiresIn: '30d'
    })
};
module.exports = {registerUser, loginUser,getMe};