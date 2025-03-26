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
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Invalid token' });
        }
        req.decoded = decoded;
        next();
    });
};

app.get('/public/config.json', (req, res) => {
    res.sendFile(path.join(__dirname, 'config.json'));
});

app.post('/save', verifyJWT, (req, res) => {
    const { contactNameField } = req.body;
    res.json({
        success: true,
        contactNameField: contactNameField
    });
});

app.post('/execute', verifyJWT, (req, res) => {
    const { inArguments } = req.body;
    const contactName = inArguments[0].contactName;
    
    console.log(`Processing contact: ${contactName}`);
    
    res.json({
        success: true,
        contactName: contactName
    });
});

app.post('/publish', verifyJWT, (req, res) => {
    res.json({ success: true });
});

app.post('/validate', verifyJWT, (req, res) => {
    res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
