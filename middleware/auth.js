import jwt from 'jsonwebtoken';

const authUser = async (req, res, next) => {
    try {
        let token;
        
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            token = authHeader.split(' ')[1];
        }
        
        if (!token && req.headers.token) {
            token = req.headers.token;
        }
        
        if (!token && req.query.token) {
            token = req.query.token;
        }

        if (!token) {
            return res.json({ 
                success: false, 
                message: 'Not Authorized - Login Again' 
            });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        const userId = decoded.id || decoded._id;
        if (!userId) {
            return res.json({ 
                success: false, 
                message: 'Invalid token format - missing user ID' 
            });
        }
        
        req.user = { 
            id: userId,
            _id: userId,
            ...decoded
        };
        
        console.log('🔓 User authenticated:', userId);
        next();
        
    } catch (error) {
        console.error('❌ Auth middleware error:', error);
        
        if (error.name === 'JsonWebTokenError') {
            return res.json({ 
                success: false, 
                message: 'Invalid token - Please login again' 
            });
        }
        
        if (error.name === 'TokenExpiredError') {
            return res.json({ 
                success: false, 
                message: 'Token expired - Please login again' 
            });
        }
        
        return res.json({ 
            success: false, 
            message: 'Authentication failed - Please login again' 
        });
    }
};

export default authUser;
