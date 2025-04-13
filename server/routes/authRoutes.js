// Description: This file contains the routes for user authentication, including login, logout, and registration.
import express from 'express';
import { login, logout, register } from '../controllers/authController.js';

const authRouter = express.Router();

// Middleware to check if the user is authenticated
authRouter.post('/register', register);
authRouter.post('/login', login);
authRouter.post('/logout', logout);

export default authRouter;