const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.text({ type: 'application/jwt' }));
app.use(express.static('public'));

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

const verifyJWT = (req, res, next) => {
    let token;
    const authHeader = req.headers.authorization || req.headers.Authorization;
    if (authHeader) {
        token = authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader;
    } else if (req.headers['content-type'] === 'application/jwt') {
        token = req.body;
    }

    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        req.decoded = decoded;
        next();
    });
};

app.get('/config.json', (req, res) => {
    res.sendFile(path.join(__dirname, 'config.json'));
});

app.post('/save', verifyJWT, (req, res) => {
    res.json({
        success: true,
        configured: true,
        metaData: { isConfigured: true }
    });
});

app.post('/execute', verifyJWT, (req, res) => {
    const { inArguments } = req.body;
    const firstName = inArguments[0].first_name || 'Unknown';
    const lastName = inArguments[0].last_name || 'Unknown';
    const street = inArguments[0].street || 'Unknown';
    const city = inArguments[0].city || 'Unknown';
    const state = inArguments[0].state || 'Unknown';
    const postalCode = inArguments[0].postal_code || 'Unknown';
    const country = inArguments[0].country || 'Unknown';
    
    console.log(`Processing contact - First Name: ${firstName}, Last Name: ${lastName}, Street: ${street}, City: ${city}, State: ${state}, Postal Code: ${postalCode}, Country: ${country}`);
    res.json({
        success: true,
        first_name: firstName,
        last_name: lastName,
        street: street,
        city: city,
        state: state,
        postal_code: postalCode,
        country: country
    });
});

app.post('/publish', verifyJWT, (req, res) => {
    res.json({
        success: true,
        configured: true,
        metaData: { isConfigured: true }
    });
});

app.post('/validate', verifyJWT, (req, res) => {
    res.json({
        success: true,
        configured: true,
        metaData: { isConfigured: true }
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});