import User from "../models/User.js";
import bcrypt from "bcrypt";
import Blacklist from '../models/Blacklist.js';
import nodemailer from "nodemailer";
import jwt from "jsonwebtoken";
import { SECRET_ACCESS_TOKEN, EMAIL_USERNAME, PASSWORD, PORT } from '../config/index.js';

function sendMail(email) {
    const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: EMAIL_USERNAME,
        pass: PASSWORD
    }
    });

    const token = jwt.sign({
        data: 'Token Data' 
    }, SECRET_ACCESS_TOKEN, { expiresIn: '10m' }  
    );    

    const mailConfigurations = {

        // It should be a string of sender/server email
        from: 'aturing201@gmail.com',

        to: email,

        // Subject of Email
        subject: 'Email Verification',
    
        // This would be the text of email body
        text: `Hi! There, You have recently visited 
        our website and entered your email.
           Please follow the given link to verify your email
           http://localhost:${PORT}/app/auth/verifymail/${token} 
           Thanks`
    };


    transporter.sendMail(mailConfigurations, function(error, info){
        if (error) throw Error(error);
        console.log('Email Sent Successfully');
        console.log(info);
    });
}


/**
 * @route POST app/auth/register
 * @desc Registers a user
 * @access Public
 */
export async function Register(req, res) {
    // get required variables from request body
    // using es6 object destructing
    const { first_name, last_name, email, password } = req.body;
    try {
        // create an instance of a user
        const newUser = new User({
            first_name,
            last_name,
            email,
            password,
        });
        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser)
            return res.status(400).json({
                status: "failed",
                data: [],
                message: "It seems you already have an account, please log in instead.",
            });
        const savedUser = await newUser.save(); // save new user into the database
        const { role, ...user_data } = savedUser._doc;
        sendMail(email);
        res.status(200).json({
            status: "success",
            data: [user_data],
            message:
                "Thank you for registering with us. Your account has been successfully created.",
        });
    } catch (err) {
        res.status(500).json({
            status: "error",
            code: 500,
            data: [],
            message: "Internal Server Error",
        });
    }
    res.end();
}



/**
 * @route POST app/auth/login
 * @desc logs in a user
 * @access Public
 */
export async function Login(req, res) {
    // Get variables for the login process
    const { email } = req.body;
    try {
        // Check if user exists
        const user = await User.findOne({ email }).select("+password");
        if (!user)
            return res.status(401).json({
                status: "failed",
                data: [],
                message:
                    "Invalid email or password. Please try again with the correct credentials.",
            });
        // if user exists
        // validate password
        const isPasswordValid = await bcrypt.compare(
            `${req.body.password}`,
            user.password
        );
        // if not valid, return unathorized response
        if (!isPasswordValid)
            return res.status(401).json({
                status: "failed",
                data: [],
                message:
                    "Invalid email or password. Please try again with the correct credentials.",
            });
        // return user info except password
        let options = {
            maxAge: 20 * 60 * 1000, // would expire in 20minutes
            httpOnly: true, // The cookie is only accessible by the web server
            secure: true,
            sameSite: "None",
        };
        const token = user.generateAccessJWT(); // generate session token for user
        res.cookie("SessionID", token, options);

        res.status(200).json({
            status: "success",
            message: "You have successfully logged in.",
        });
    } catch (err) {
        res.status(500).json({
            status: "error",
            code: 500,
            data: [],
            message: "Internal Server Error",
        });
    }
    res.end();
}

export async function Logout(req, res) {
    try {
      const authHeader = req.headers['cookie']; // get the session cookie from request header
      if (!authHeader) return res.sendStatus(204); // No content
      const cookie = authHeader.split('=')[1]; // If there is, split the cookie string to get the actual jwt token
      const accessToken = cookie.split(';')[0];
      const checkIfBlacklisted = await Blacklist.findOne({ token: accessToken }); // Check if that token is blacklisted
      // if true, send a no content response.
      if (checkIfBlacklisted) return res.sendStatus(204);
      // otherwise blacklist token
      const newBlacklist = new Blacklist({
        token: accessToken,
      });
      await newBlacklist.save();
      // Also clear request cookie on client
      res.setHeader('Clear-Site-Data', '"cookies"');
      res.status(200).json({ message: 'You are logged out!' });
    } catch (err) {
      res.status(500).json({
        status: 'error',
        message: 'Internal Server Error',
      });
    }
    res.end();
  }
  export async function VerifyMail(req, res){
    const {token} = req.params;

    // Verifying the JWT token 
    jwt.verify(token, SECRET_ACCESS_TOKEN, function(err, decoded) {
        if (err) {
            console.log(err);
            res.send("Email verification failed, possibly the link is invalid or expired");
        }
        else {
            res.send("Email verifified successfully");
        }
    });
}

export const RequestPasswordReset = async (req, res, next) => {
    const { email } = req.body;
    try {
      const user = await User.findOne({ email });
      if (!user) return res.status(404).json({ message: "User doesn't exist" });
  
      const secret = SECRET_ACCESS_TOKEN + user.password;
      const token = jwt.sign({email: user.email }, secret, { expiresIn: '1h' });
  
      const resetURL = `http://localhost:5005/resetpassword?email=${user.email}&token=${token}`;
  
      const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: EMAIL_USERNAME,
          pass: PASSWORD,
        },
      });
  
      const mailOptions = {
        to: user.email,
        from: EMAIL_USERNAME,
        subject: 'Password Reset Request',
        text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
        Please click on the following link, or paste this into your browser to complete the process:\n\n
        ${resetURL}\n\n
        If you did not request this, please ignore this email and your password will remain unchanged.\n`,
      };
  
      await transporter.sendMail(mailOptions);
  
      res.status(200).json({ message: 'Password reset link sent' });
    } catch (error) {
      res.status(500).json({ message: 'Something went wrong' });
    }
  };

  export const ResetPassword = async (req, res, next) => {
    const { email, token } = req.query;
    const { password } = req.body;
    console.log({ email });
    try {
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(400).json({ message: "User not exists!" });
      }
  
      const secret = SECRET_ACCESS_TOKEN + user.password;
  
  
  
      const verify = jwt.verify(token, secret);
      await User.updateOne(
        {
          email: email,
        },
        {
          $set: {
            password: password,
          },
        }
      );
  
  
      await user.save();
  
      res.status(200).json({ message: 'Password has been reset' });
    } catch (error) {
      console.log(error);
      res.status(500).json({ message: 'Something went wrong' });
    }
  };