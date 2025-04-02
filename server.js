const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const fetch = require('node-fetch'); // Import node-fetch
const app = express();

app.use(express.json());
app.use(express.text({ type: 'application/jwt' }));

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const APP_URL = process.env.APP_URL || 'https://salesforce-marketing-cloud-25ceb7c2d745.herokuapp.com';
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;

const verifyJWT = (req, res, next) => {
    console.log('Request Headers:', JSON.stringify(req.headers));
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

// Serve dynamic index.html at the root route (before static middleware)
app.get('/', (req, res) => {
    console.log('Serving dynamic index.html for request:', req.url);
    const indexPath = path.join(__dirname, 'public', 'index.html');
    fs.readFile(indexPath, 'utf8', (err, data) => {
        if (err) {
            console.error('Error reading index.html:', err);
            return res.status(500).send('Error loading index.html');
        }
        // Inject the APP_URL into the HTML as a global variable
        const modifiedData = data.replace(
            '<!-- APP_URL -->',
            `<script>window.APP_URL = "${APP_URL}";</script>`
        );
        // Set headers to prevent caching
        res.set({
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            'Surrogate-Control': 'no-store'
        });
        res.send(modifiedData);
        console.log('Dynamic index.html served with APP_URL:', APP_URL);
    });
});

// Serve dynamic config.json
app.get('/config.json', (req, res) => {
    console.log('Serving dynamic config.json');
    const configTemplate = {
        "workflowApiVersion": "1.1",
        "metaData": {
            "icon": "images/pcmlogo.png",
            "category": "Messages",
            "isConfigured": false
        },
        "type": "REST",
        "lang": {
            "en-US": {
                "name": "PCM Direct Mail",
                "description": "Dynamically processes contact details from the entry source Data Extension"
            }
        },
        "arguments": {
            "execute": {
                "inArguments": [],
                "outArguments": [],
                "url": `${APP_URL}/execute`,
                "verb": "POST",
                "body": "",
                "header": "",
                "format": "json",
                "useJwt": true,
                "timeout": 10000
            }
        },
        "configurationArguments": {
            "save": {
                "url": `${APP_URL}/save`,
                "verb": "POST",
                "useJwt": true,
                "configured": true
            },
            "publish": {
                "url": `${APP_URL}/publish`,
                "verb": "POST",
                "useJwt": true,
                "configured": true
            },
            "validate": {
                "url": `${APP_URL}/validate`,
                "verb": "POST",
                "useJwt": true,
                "configured": true
            }
        },
        "userInterfaces": {
            "configModal": {
                "url": `${APP_URL}/`,
                "height": 600,
                "width": 800,
                "fullscreen": false,
                "useJwt": true // Add this line!
            }
        },
        "schema": {
            "arguments": {
                "execute": {
                    "inArguments": [
                        {
                            "dataExtension": {
                                "dataType": "Text",
                                "isNullable": false,
                                "direction": "in"
                            },
                            "first_name_field": {
                                "dataType": "Text",
                                "isNullable": false,
                                "direction": "in"
                            },
                            "first_name": {
                                "dataType": "Text",
                                "isNullable": false,
                                "direction": "in"
                            },
                            "last_name_field": {
                                "dataType": "Text",
                                "isNullable": true,
                                "direction": "in"
                            },
                            "last_name": {
                                "dataType": "Text",
                                "isNullable": true,
                                "direction": "in"
                            },
                            "street_field": {
                                "dataType": "Text",
                                "isNullable": true,
                                "direction": "in"
                            },
                            "street": {
                                "dataType": "Text",
                                "isNullable": true,
                                "direction": "in"
                            },
                            "city_field": {
                                "dataType": "Text",
                                "isNullable": true,
                                "direction": "in"
                            },
                            "city": {
                                "dataType": "Text",
                                "isNullable": true,
                                "direction": "in"
                            },
                            "state_field": {
                                "dataType": "Text",
                                "isNullable": true,
                                "direction": "in"
                            },
                            "state": {
                                "dataType": "Text",
                                "isNullable": true,
                                "direction": "in"
                            },
                            "postal_code_field": {
                                "dataType": "Text",
                                "isNullable": true,
                                "direction": "in"
                            },
                            "postal_code": {
                                "dataType": "Text",
                                "isNullable": true,
                                "direction": "in"
                            },
                            "country_field": {
                                "dataType": "Text",
                                "isNullable": true,
                                "direction": "in"
                            },
                            "country": {
                                "dataType": "Text",
                                "isNullable": true,
                                "direction": "in"
                            }
                        }
                    ]
                }
            }
        }
    };
    res.json(configTemplate);
    console.log('Dynamic config.json served with APP_URL:', APP_URL);
});

// Serve static files (after the dynamic routes)
app.use(express.static('public'));

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
    const { inArguments } = req.decoded;
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

// Endpoint to get the authentication token
async function getDesignToken() {
    if ( !CLIENT_ID || !CLIENT_SECRET) {
        console.error('AUTH_URL, CLIENT_ID, or CLIENT_SECRET environment variables not set.');
        throw new Error('Authentication credentials not configured on the server.');
    }

    try {
        const response = await fetch('https://v3.pcmintegrations.com/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                apiKey: CLIENT_ID,
                apiSecret: CLIENT_SECRET
            })
        });

        if (!response.ok) {
            console.error('Error getting design token:', response.status, response.statusText);
            throw new Error(`Failed to get design token: ${response.statusText}`);
        }
        const data = await response.json();
        if (data && data.token) { // Assuming the token is in a 'token' field
            console.log('Design token retrieved successfully');
            return data.token;
        } else {
            console.error('Design token not found in response:', data);
            throw new Error('Design token not found in authentication response.');
        }
    } catch (error) {
        console.error('Error during design token retrieval:', error);
        throw error;
    }
}

// New endpoint to fetch designs, protected by JWT verification
app.get('/getDesigns',  async (req, res) => {
    console.log('getDesigns endpoint called');
    console.log('Request Headers:', JSON.stringify(req.headers));

    try {
        const authToken = await getDesignToken();
        const response = await fetch('https://v3.pcmintegrations.com/design', {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'Authorization': `Bearer ${authToken}`
            }
        });

        if (!response.ok) {
            console.error('Error fetching designs from external API:', response.status, response.statusText);
            return res.status(response.status).json({ error: `Failed to fetch designs: ${response.statusText}` });
        }
        const data = await response.json();
        res.json(data);
        console.log('Designs data fetched successfully from external API');
    } catch (error) {
        console.error('Error fetching designs:', error);
        res.status(500).json({ error: `Failed to fetch designs: ${error.message}` });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});