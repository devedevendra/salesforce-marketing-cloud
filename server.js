const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.static('public'));

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

const verifyJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        console.log('No token provided in request');
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
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
    const name = inArguments[0].name;
    const email = inArguments[0].email;
    
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