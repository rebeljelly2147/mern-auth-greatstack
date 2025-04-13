// Description: This file contains the routes for user authentication, including login, logout, and registration.
import express from 'express';
import { login, logout, register, sendVerifyOtp, verifyEmail } from '../controllers/authController.js';
import userAuth from '../middleware/userAuth.js';

const authRouter = express.Router();

// Middleware to check if the user is authenticated
authRouter.post('/register', register);
authRouter.post('/login', login);
authRouter.post('/logout', logout);
authRouter.post('/sendVerifyOtp',userAuth, sendVerifyOtp);
authRouter.post('/verifyAccount',userAuth, verifyEmail);

export default authRouter;