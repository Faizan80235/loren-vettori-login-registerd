import express from "express";
import cors from "cors";
import rateLimit, { ipKeyGenerator } from "express-rate-limit";
import helmet from "helmet";
import "dotenv/config";
import connectDB from "../config/mongodb.js";
import userRouter from "../routes/userRoute.js";
import serverless from 'serverless-http';
const app = express();
const port = process.env.PORT || 5000;
const isDevelopment = process.env.NODE_ENV !== 'production';
const isVercel = process.env.VERCEL === '1';

// Database connection with retry logic for serverless
let dbConnected = false;
const initDB = async () => {
    if (!dbConnected) {
        try {
            await connectDB();
            dbConnected = true;
            console.log('✅ Database connected');
        } catch (error) {
            console.error('❌ Database connection failed:', error);
        }
    }
};

// Initialize DB connection
initDB();

// Middleware to ensure DB connection on each request (serverless optimization)
app.use(async (req, res, next) => {
    if (!dbConnected) {
        await initDB();
    }
    next();
});

// Security middlewares
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "blob:", "*"],
        },
    },
}));

// Rate limiting configuration - Fixed for express-rate-limit v7
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: isDevelopment ? 1000 : 10,
    message: {
        success: false,
        message: "Too many authentication attempts, please try again later."
    },
    keyGenerator: (req) => {
        // Fixed: Use ipKeyGenerator for proper IPv6 support
        return `${ipKeyGenerator(req)}-${req.path}`;
    },
    standardHeaders: true,
    legacyHeaders: false,
    // Fixed: Replace onLimitReached with handler
    handler: (req, res) => {
        console.log(`🔒 Auth rate limit exceeded for IP: ${req.ip}, Path: ${req.path}`);
        res.status(429).json({
            success: false,
            message: "Too many authentication attempts, please try again later."
        });
    }
});

// CORS configuration
const corsOptions = {
    origin: [
        process.env.FRONTEND_URL || "https://loren-vettori-frontend.netlify.app",
        "http://localhost:5173",
        "https://loren-vettori-frontend.netlify.app"
    ],
    credentials: true,
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
        'Content-Type', 
        'Authorization', 
        'X-Requested-With',
        'token'
    ]
};

// Middlewares
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging middleware
app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    if (isDevelopment) {
        console.log(`${timestamp} - ${req.method} ${req.path}`);
    }
    next();
});

// ==========================================
// API ROUTES
// ==========================================
// Auth routes with rate limiting
app.use("/api/user", (req, res, next) => {
    if (isDevelopment) {
        console.log(`👤 Auth rate limiter check: ${req.method} ${req.path} from ${req.ip}`);
    }
    return authLimiter(req, res, next);
}, userRouter);

// ==========================================
// UTILITY ENDPOINTS
// ==========================================
// Health check endpoint
app.get("/health", (req, res) => {
    res.json({ 
        success: true, 
        message: "Server is healthy",
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        isVercel,
        dbConnected
    });
});

app.get("/", (req, res) => {
    res.json({ 
        success: true, 
        message: "Auth API is running",
        version: "1.0.0",
        environment: process.env.NODE_ENV || 'development',
        platform: isVercel ? 'Vercel Serverless' : 'Node.js'
    });
});

// ==========================================
// ERROR HANDLERS
// ==========================================
// 404 handler
app.use("*", (req, res) => {
    console.log(`❌ 404 - Route not found: ${req.method} ${req.originalUrl}`);
    res.status(404).json({ 
        success: false, 
        message: "Route not found" 
    });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error("Global error handler:", err.stack);
    
    if (err.name === 'ValidationError') {
        return res.status(400).json({
            success: false,
            message: "Validation error",
            errors: Object.values(err.errors).map(e => e.message)
        });
    }
    
    if (err.name === 'CastError') {
        return res.status(400).json({
            success: false,
            message: "Invalid ID format"
        });
    }
    
    if (err.code === 11000) {
        return res.status(400).json({
            success: false,
            message: "Duplicate field value"
        });
    }
    
    res.status(500).json({ 
        success: false, 
        message: process.env.NODE_ENV === 'production' 
            ? "Something went wrong!" 
            : err.message
    });
});

// Start server (for local development)
if (!isVercel) {
    app.listen(port, () => {
        console.log(`🚀 Server is running on port ${port}`);
        console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
        console.log(`🌐 Local: http://localhost:${port}`);
    });
}

// Export for Vercel serverless function
export default serverless(app);