import userModel from "../models/userModel.js";
import validator from 'validator';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const createToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '7d' })
}

const createVerificationToken = () => {
    return crypto.randomBytes(32).toString('hex');
}

const loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                message: "Email and password are required" 
            });
        }

        // Check if this is admin credentials first
        if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {
            const token = jwt.sign(
                { email, isAdmin: true },
                process.env.JWT_SECRET,
                { expiresIn: "24h" }
            );
            return res.status(200).json({ 
                success: true, 
                token, 
                role: "admin",
                message: "Admin login successful"
            });
        }

        // Find user in database
        const user = await userModel.findOne({ email: email.toLowerCase().trim() });
        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: "Invalid email or password"
            });
        }

        // Check if email is verified
        if (!user.isEmailVerified) {
            return res.status(401).json({ 
                success: false, 
                message: "Please verify your email address before logging in. Check your inbox for verification link.",
                emailVerified: false,
                email: user.email
            });
        }

        // Compare password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ 
                success: false, 
                message: "Invalid email or password" 
            });
        }

        // Update last login
        user.lastLogin = new Date();
        await user.save();

        // Create token
        const token = jwt.sign(
            { id: user._id, isAdmin: false }, 
            process.env.JWT_SECRET, 
            { expiresIn: "7d" }
        );

        res.status(200).json({ 
            success: true, 
            token, 
            role: "user",
            message: "Login successful",
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                isEmailVerified: user.isEmailVerified
            }
        });

    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ 
            success: false, 
            message: "Server error. Please try again later." 
        });
    }
};

const registerUser = async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ 
                success: false, 
                message: "All fields are required" 
            });
        }

        const exists = await userModel.findOne({ email: email.toLowerCase().trim() });
        if (exists) {
            return res.status(409).json({ 
                success: false, 
                message: "User already exists with this email" 
            });
        }

        if (!validator.isEmail(email)) {
            return res.status(400).json({ 
                success: false, 
                message: "Please enter a valid email" 
            });
        }

        if (password.length < 8) {
            return res.status(400).json({ 
                success: false, 
                message: "Password must be at least 8 characters long" 
            });
        }

        const hasNumber = /\d/.test(password);
        const hasLetter = /[a-zA-Z]/.test(password);
        if (!hasNumber || !hasLetter) {
            return res.status(400).json({ 
                success: false, 
                message: "Password must contain both letters and numbers" 
            });
        }

        // Create verification token
        const verificationToken = createVerificationToken();

        const newUser = new userModel({
            name: name.trim(),
            email: email.toLowerCase().trim(),
            password: password,
            isEmailVerified: false,
            emailVerificationToken: verificationToken,
            emailVerificationExpires: Date.now() + 24 * 60 * 60 * 1000
        });

        const savedUser = await newUser.save();
        
        // Note: Email sending removed for simplicity
        console.log(`Verification token for ${savedUser.email}: ${verificationToken}`);
        
        res.status(201).json({ 
            success: true, 
            message: "Registration successful! Please check your email to verify your account.",
            user: {
                id: savedUser._id,
                name: savedUser.name,
                email: savedUser.email,
                isEmailVerified: savedUser.isEmailVerified
            }
        });

    } catch (error) {
        console.error("Registration error:", error);
        
        if (error.code === 11000) {
            return res.status(409).json({ 
                success: false, 
                message: "Email already exists" 
            });
        }
        
        res.status(500).json({ 
            success: false, 
            message: "Registration failed. Please try again." 
        });
    }
}

const verifyEmail = async (req, res) => {
    try {
        const { token } = req.body;

        if (!token) {
            return res.status(400).json({
                success: false,
                message: "Verification token is required"
            });
        }

        const user = await userModel.findOne({
            emailVerificationToken: token,
            emailVerificationExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({
                success: false,
                message: "Invalid or expired verification token"
            });
        }

        user.isEmailVerified = true;
        user.emailVerificationToken = undefined;
        user.emailVerificationExpires = undefined;
        user.emailVerifiedAt = new Date();
        await user.save();

        const authToken = createToken(user._id);

        res.status(200).json({
            success: true,
            message: "Email verified successfully! You can now login.",
            token: authToken,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                isEmailVerified: user.isEmailVerified
            }
        });

    } catch (error) {
        console.error("Email verification error:", error);
        res.status(500).json({
            success: false,
            message: "Verification failed. Please try again."
        });
    }
};

const adminLogin = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                message: "Email and password are required" 
            });
        }

        if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {
            const token = jwt.sign({
                email: process.env.ADMIN_EMAIL,
                isAdmin: true
            }, process.env.JWT_SECRET, { expiresIn: '24h' });
            
            res.status(200).json({ 
                success: true, 
                token,
                message: "Admin login successful"
            });
        } else {
            res.status(401).json({ 
                success: false, 
                message: "Invalid admin credentials" 
            });
        }
    } catch (error) {
        console.error("Admin login error:", error);
        res.status(500).json({ 
            success: false, 
            message: "Admin login failed. Please try again." 
        });
    }
}

export { loginUser, registerUser, adminLogin, verifyEmail };
