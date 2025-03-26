const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.text({ type: 'application/jwt' }));
app.use(express.static('public'));

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

const verifyJWT = (req, res, next) => {
    console.log('Verifying JWT for request:', req.method, req.url);
    let token;
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (authHeader) {
        console.log('Authorization header found:', authHeader);
        token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader;
    } else if (req.headers['content-type'] === 'application/jwt') {
        console.log('Content-Type is application/jwt, using request body as token');
        token = req.body;
    }

    if (!token) {
        console.error('No token provided in request');
        return res.status(401).json({ error: 'No token provided' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            console.error('JWT verification failed:', err.message);
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
    console.log('Save endpoint called with body:', req.body);
    console.log('Decoded JWT:', JSON.stringify(req.decoded));
    res.json({
        success: true,
        configured: true,
        metaData: { isConfigured: true }
    });
    console.log('Save endpoint responded with success');
});

app.post('/execute', verifyJWT, (req, res) => {
    console.log('Execute endpoint called with body:', JSON.stringify(req.body));
    console.log('Decoded JWT:', JSON.stringify(req.decoded));
    const { inArguments } = req.body;
    if (!inArguments || !inArguments[0]) {
        console.error('No inArguments provided in execute request');
        return res.status(400).json({ error: 'No inArguments provided' });
    }

    const args = inArguments[0];
    const firstName = args.first_name || 'Unknown';
    const lastName = args.last_name || 'Unknown';
    const street = args.street || 'Unknown';
    const city = args.city || 'Unknown';
    const state = args.state || 'Unknown';
    const postalCode = args.postal_code || 'Unknown';
    const country = args.country || 'Unknown';

    console.log(`Processing contact - First Name: ${firstName}, Last Name: ${lastName}, Street: ${street}, City: ${city}, State: ${state}, Postal Code: ${postalCode}, Country: ${country}`);

    const response = {
        success: true,
        first_name: firstName,
        last_name: lastName,
        street: street,
        city: city,
        state: state,
        postal_code: postalCode,
        country: country
    };
    console.log('Execute endpoint responding with:', JSON.stringify(response));
    res.json(response);
});

app.post('/publish', verifyJWT, (req, res) => {
    console.log('Publish endpoint called with body:', req.body);
    console.log('Decoded JWT:', JSON.stringify(req.decoded));
    res.json({
        success: true,
        configured: true,
        metaData: { isConfigured: true }
    });
    console.log('Publish endpoint responded with success');
});

app.post('/validate', verifyJWT, (req, res) => {
    console.log('Validate endpoint called with body:', req.body);
    console.log('Decoded JWT:', JSON.stringify(req.decoded));
    res.json({
        success: true,
        configured: true,
        metaData: { isConfigured: true }
    });
    console.log('Validate endpoint responded with success');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});