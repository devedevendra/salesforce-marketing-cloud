const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');
const app = express();

app.use(express.json()); // Ensures req.body is parsed for JSON or text
app.use(express.text({ type: 'application/jwt' })); // Parse application/jwt as text
app.use(express.static('public'));

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

const verifyJWT = (req, res, next) => {
    console.log('Request headers:', JSON.stringify(req.headers));
    console.log('Request body:', req.body);

    let token;

    // Check Authorization header first (for compatibility with manual tests)
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (authHeader) {
        token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader;
        console.log('Token from Authorization header:', token);
    }

    // If no token in header and Content-Type is application/jwt, use body
    if (!token && req.headers['content-type'] === 'application/jwt') {
        token = req.body; // Body should be the raw JWT string
        console.log('Token from request body (application/jwt):', token);
    }

    if (!token) {
        console.log('No token provided in request');
        return res.status(401).json({ error: 'No token provided' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            console.log('JWT verification failed:', err.message);
            return res.status(401).json({ error: 'Invalid token' });
        }
        console.log('JWT verified successfully, decoded:', JSON.stringify(decoded));
        req.decoded = decoded;
        next();
    });
};

app.get('/config.json', (req, res) => {
    console.log('Serving config.json');
    res.sendFile(path.join(__dirname, 'config.json'));
});

app.post('/save', verifyJWT, (req, res) => {
    console.log('Save endpoint called with body:', JSON.stringify(req.body));
    const response = {
        success: true,
        configured: true,
        metaData: { isConfigured: true }
    };
    console.log('Save endpoint responding with:', JSON.stringify(response));
    res.json(response);
});

app.post('/execute', verifyJWT, (req, res) => {
    console.log('Execute endpoint called with body:', JSON.stringify(req.body));
    const { inArguments } = req.body;
    const name = inArguments[0].name || 'Unknown';
    const email = inArguments[0].email || 'Unknown';
    
    console.log(`Processing contact - Name: ${name}, Email: ${email}`);
    const response = {
        success: true,
        name: name,
        email: email
    };
    console.log('Execute endpoint responding with:', JSON.stringify(response));
    res.json(response);
});

app.post('/publish', verifyJWT, (req, res) => {
    console.log('Publish endpoint called with body:', JSON.stringify(req.body));
    const response = {
        success: true,
        configured: true,
        metaData: { isConfigured: true }
    };
    console.log('Publish endpoint responding with:', JSON.stringify(response));
    res.json(response);
});

app.post('/validate', verifyJWT, (req, res) => {
    console.log('Validate endpoint called with body:', JSON.stringify(req.body));
    const response = {
        success: true,
        configured: true,
        metaData: { isConfigured: true }
    };
    console.log('Validate endpoint responding with:', JSON.stringify(response));
    res.json(response);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});