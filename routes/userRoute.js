import express from 'express'
import { loginUser, registerUser, adminLogin, verifyEmail } from '../controller/userController.js'
import authUser from '../middleware/auth.js'
import userModel from '../models/userModel.js'

const userRouter = express.Router();

// Authentication routes
userRouter.post('/register', registerUser)
userRouter.post('/login', loginUser)
userRouter.post('/admin', adminLogin)

// Email verification routes
userRouter.post('/verify-email', verifyEmail)

// Test route
userRouter.get('/verify-status/:userId', authUser, async (req, res) => {
    try {
        const { userId } = req.params;
        const user = await userModel.findById(userId).select('isEmailVerified emailVerifiedAt');
        
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        res.json({
            success: true,
            isEmailVerified: user.isEmailVerified,
            emailVerifiedAt: user.emailVerifiedAt
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Failed to check verification status'
        });
    }
});

export default userRouter;