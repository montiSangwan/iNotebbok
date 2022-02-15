const express = require('express');
const router = express.Router();

const User = require('../models/User');

const { body, validationResult } = require('express-validator');  // to validate the name , email and password
const bcrypt = require('bcryptjs');   // to encrypt the password & It is a method for salt and hashing passwords
var jwt = require('jsonwebtoken');

const fetchuser = require('../middleware/fetchuser');  // we go one step back to reach middleware so we use ..

const JWT_SECRET = "Montisassw@asnsds";

//ROUTE 1 : Create a user using POST "/api/auth/createuser". No login required
router.post('/createuser', [
        body('name', 'Enter a valid name').isLength({ min: 3 }),
        body('email', 'Enter a valid email').isEmail(),  // email must be an email
        body('password', 'Password must be atleast 5 characters').isLength({ min: 5 }),  // password must be at least 5 chars long
    ] , async (req, res)=>{
    
    let success = false;
    // If there are errors, return Bad request and the errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({success , errors: errors.array() });
    }

    try{
        // Check whether the user with the same email exist already and it return promise so we write await
        let user = await User.findOne({email: req.body.email});
        if(user){
            return res.status(400).json({ success , errors: "Sorry a user with this email is already exist" });
        }

        const salt = await bcrypt.genSalt(10);  // to generate the salt
        const secPass = await bcrypt.hash(req.body.password , salt);  // adding salt to the password
        // we write await because it is asynchronous fun and it return promise

        // Create a new user 
        user = await User.create({
            name: req.body.name,
            email: req.body.email,
            password: secPass,
        })

        const data={
            user: {
                id: user.id
            }
        }

        const authtoken = jwt.sign(data , JWT_SECRET);
        success = true;
        res.json({success , authtoken});
        //res.json(user);

    } catch(error){
        console.error(error.message);
        res.send(500).send("Some error occured");
    }
})

//ROUTE 2 : Authenticate a user using POST "/api/auth/login". No login required
router.post('/login', [
    body('email', 'Enter a valid email').isEmail(),  // email must be an email
    body('password', 'Password cannot be blank').exists()  
    ] , async (req, res)=>{

    let success = false;    
    // If there are errors, return Bad request and the errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({success , errors: errors.array() });
    }

    const {email , password} = req.body;
    try {
        let user = await User.findOne({email});
        if(!user){
            return res.status(400).json({success , error: "Please try to login with correct credentials"});
        }

        const passwordCompare = await bcrypt.compare(password , user.password); // it is an asynchronous fun
        if(!passwordCompare){
            return res.status(400).json({success , error: "Please try to login with correct credentials"});
        }

        const data = {
            user: {
                id: user.id
            }
        }

        const authtoken = jwt.sign(data , JWT_SECRET);
        success = true;
        res.json({success , authtoken});

    } catch (error) {
        console.error(error.message);
        res.send(500).send("Some error occured");
    }
})

//ROUTE 3 : Get a logged in user details using POST "/api/auth/getuser". Login required
router.post('/getuser', fetchuser ,async (req, res)=>{
    try {
        userId = req.user.id;  // we can use this bcoz we are using middleware - fetchuser
        const user = await User.findById(userId).select('-password');
        res.send(user);

    } catch (error) {
        console.error(error.message);
        res.send(500).send("Some error occured");
    }
})

module.exports = router