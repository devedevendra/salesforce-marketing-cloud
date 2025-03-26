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

app.get('/config.json', (req, res) => {
    res.sendFile(path.join(__dirname, 'config.json'));
});

app.post('/save', verifyJWT, (req, res) => {
    res.json({ success: true });
});

app.post('/execute', verifyJWT, (req, res) => {
    const { inArguments } = req.body;
    const name = inArguments[0].name;
    const email = inArguments[0].email;
    
    console.log(`Processing contact - Name: ${name}, Email: ${email}`);
    
    res.json({
        success: true,
        name: name,
        email: email
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