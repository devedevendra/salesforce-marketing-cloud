const crypto = require('node:crypto'); // Added for encryption/decryption
const express = require('express');
const jwt = require('jsonwebtoken');

const path = require('path');
const axios = require('axios');
const fs = require('fs');
const fetch = require('node-fetch'); // Import node-fetch
const app = express();


app.use(express.json());
app.use(express.text({ type: 'application/jwt' }));

let JWT_SECRET =  '';
const APP_URL = process.env.APP_URL || 'https://salesforce-marketing-cloud-25ceb7c2d745.herokuapp.com';
//const CLIENT_ID = process.env.CLIENT_ID;
//const CLIENT_SECRET = process.env.CLIENT_SECRET;
const CIPHER_KEY = process.env.CIPHER_KEY;

// --- START: Encryption and Decryption Functions ---
/**
 * Encrypts a string using AES-GCM with a password-derived key.
 * @param {string} plaintext The string to encrypt.
 * @param {string} password The password to derive the encryption key from.
 * @returns {Promise<string>} A Promise that resolves to the Base64 encoded encrypted string (salt + iv + ciphertext).
 */
async function encryptString_node(plaintext, password) {
    const enc = new TextEncoder();

    // Generate salt (16 bytes)
    const salt = crypto.webcrypto.getRandomValues(new Uint8Array(16));
    // Generate IV (12 bytes for AES-GCM)
    const iv = crypto.webcrypto.getRandomValues(new Uint8Array(12));

    // Derive key from password using PBKDF2
    const keyMaterial = await crypto.webcrypto.subtle.importKey(
        "raw",
        enc.encode(password), // Password as BufferSource
        "PBKDF2",
        false, // not extractable
        ["deriveKey"]
    );

    const key = await crypto.webcrypto.subtle.deriveKey(
        {
        name: "PBKDF2",
        salt: salt, // Salt as BufferSource
        iterations: 100000,
        hash: "SHA-256",
        },
        keyMaterial, // Base key
        { name: "AES-GCM", length: 256 }, // Algorithm and key length for derived key
        false, // not extractable
        ["encrypt"] // Key usages
    );

    // Encrypt the plaintext
    const ciphertextBuffer = await crypto.webcrypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, // Algorithm parameters (IV)
        key, // Encryption key
        enc.encode(plaintext) // Plaintext as BufferSource
    );

    // ciphertextBuffer is an ArrayBuffer. Convert it to Uint8Array.
    const ciphertext = new Uint8Array(ciphertextBuffer);

    // Concatenate salt + iv + ciphertext
    const combined = new Uint8Array(salt.length + iv.length + ciphertext.length);
    combined.set(salt, 0); // Add salt at the beginning
    combined.set(iv, salt.length); // Add IV after salt
    combined.set(ciphertext, salt.length + iv.length); // Add ciphertext after IV

    // Convert the combined Uint8Array to a Base64 string
    return Buffer.from(combined).toString('base64');
}

/**
 * Decrypts a Base64 encoded string (salt + iv + ciphertext) using AES-GCM.
 * @param {string} encryptedString The Base64 encoded string to decrypt.
 * @param {string} decryptionKey The password used for encryption.
 * @returns {Promise<string>} A Promise that resolves to the original plaintext string.
 */
async function decryptString_node(encryptedString, decryptionKey) {
    const enc = new TextEncoder(); // For encoding the password
    const dec = new TextDecoder(); // For decoding the decrypted data

    // Convert Base64 string back to Uint8Array
    // Buffer.from(string, 'base64') returns a Buffer, which is a Uint8Array subclass
    const dataBuffer = Buffer.from(encryptedString, 'base64');
    const data = new Uint8Array(dataBuffer); // Ensure it's a Uint8Array view if needed for strictness

    // Extract salt, IV, and ciphertext
    // Salt is the first 16 bytes
    const salt = data.slice(0, 16);
    // IV is the next 12 bytes
    const iv = data.slice(16, 28); // 16 (salt) + 12 (iv) = 28
    // Ciphertext is the rest
    const ciphertext = data.slice(28);

    // Derive key from password (must use the same salt and parameters as encryption)
    const keyMaterial = await crypto.webcrypto.subtle.importKey(
        "raw",
        enc.encode(decryptionKey),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    const key = await crypto.webcrypto.subtle.deriveKey(
        {
        name: "PBKDF2",
        salt: salt, // Use the extracted salt
        iterations: 100000,
        hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"] // Key usage for decryption
    );

    // Decrypt the ciphertext
    const decryptedBuffer = await crypto.webcrypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv }, // Algorithm parameters (extracted IV)
        key, // Decryption key
        ciphertext // Ciphertext as BufferSource
    );

    // decryptedBuffer is an ArrayBuffer. Decode it to a string.
    return dec.decode(decryptedBuffer);
}
// --- END: Encryption and Decryption Functions ---

const verifyJWT = async (req, res, next) => {
    console.log('Request Headers:', JSON.stringify(req.headers));
    console.log('Verifying JWT for request:', req.method, req.url);
    let unverifiedPayload;
    let peekedMid;

    try {
        unverifiedPayload = jwt.decode(req.body);
        if (unverifiedPayload &&
            unverifiedPayload.inArguments &&
            unverifiedPayload.inArguments.length > 0 &&
            unverifiedPayload.inArguments[0].mid) {
            peekedMid = unverifiedPayload.inArguments[0].mid;
            console.log('Peeked MID:', peekedMid);

            const pcmLoginApiUrl = 'https://apiqa.pcmintegrations.com/auth/marketing-cloud-login';

            console.log(`Checking if user exists: ${pcmLoginApiUrl}`);
            let encryptedMID = await encryptString_node(peekedMid, CIPHER_KEY);
            const response = await fetch(pcmLoginApiUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    uniqueID: encryptedMID
                })
            });

            const responseBody = await response.json(); // Always try to parse the JSON body
            console.log('response:',responseBody);
            console.log('PCM API Response Status Code:', response.status);
            if (response.status === 200) {
                // 1. 200 OK
                JWT_SECRET = responseBody.jwtSecret;
                
            } else if (response.status === 404) {
                // 2. 404 Not Found
                return res.status(200).json({
                    success: true,
                    existingUser: false,
                    // You might want to include the error message from the response if needed
                    message: responseBody.error && responseBody.error.data && responseBody.error.data[0] ? responseBody.error.data[0].message : "Unable to locate account",
                    errorCode: responseBody.error ? responseBody.error.code : 404
                });
            } else if (response.status === 500) {
                // 3. 500 Internal Server Error
                let errorMessage = "An unexpected error has occurred.";
                if (responseBody.error && responseBody.error.data && responseBody.error.data[0] && responseBody.error.data[0].message) {
                    errorMessage = responseBody.error.data[0].message;
                }
                return res.status(500).json({
                    success: false,
                    message: errorMessage,
                    errorCode: responseBody.error ? responseBody.error.code : 500
                });
            } else {
                // Handle other unexpected statuses
                let errorMessage = `Unexpected status code: ${response.status}`;
                if (responseBody.error && responseBody.error.message) {
                    errorMessage = responseBody.error.message;
                } else if (responseBody.message) {
                    errorMessage = responseBody.message;
                }
                return res.status(500).json({
                    success: false,
                    message: errorMessage,
                    errorCode: response.status,
                    details: responseBody // include the full body for debugging if desired
                });
            }

        } else {
            console.error('MID not found in the expected location within unverified JWT payload:', unverifiedPayload);
            return res.status(400).send('Bad Request: MID missing or JWT structure incorrect.');
        }
    } catch (e) {
        console.error('Error decoding JWT for peeking:', e.message);
        return res.status(400).send('Bad Request: Invalid JWT structure.');
    }
    console.log('unverifiedPayload:', JSON.stringify(unverifiedPayload));
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
                "height": 800,
                "width": 1000,
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
                            },
                            "selectedDesignId": {
                                "dataType": "Text",
                                "isNullable": true,
                                "direction": "in"
                            },
                            "mid": {
                                "dataType": "Text",
                                "isNullable": true,
                                "direction": "in"
                            },
                            "rfirst_name": {
                                "dataType": "Text",
                                "isNullable": false,
                                "direction": "in"
                            },
                            "rlast_name": {
                                "dataType": "Text",
                                "isNullable": true,
                                "direction": "in"
                            },
                            "rstreet": {
                                "dataType": "Text",
                                "isNullable": true,
                                "direction": "in"
                            },
                            "rcity": {
                                "dataType": "Text",
                                "isNullable": true,
                                "direction": "in"
                            },
                            "rstate": {
                                "dataType": "Text",
                                "isNullable": true,
                                "direction": "in"
                            },
                            "rpostalCode": {
                                "dataType": "Text",
                                "isNullable": true,
                                "direction": "in"
                            },
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
    console.log('Save endpoint called with body:', JSON.stringify(req.body));
    console.log('Decoded JWT:', JSON.stringify(req.decoded));
    res.json({
        success: true,
        configured: true,
        metaData: { isConfigured: true }
    });
    console.log('Save endpoint responded with success');
});

app.post('/execute', verifyJWT, async (req, res) => {
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
    const designId =  parseInt(args.selectedDesignId || 'Unknown');
    const mid  =  (args.mid || 'Unknown');

    const rfirstName = args.rfirst_name || 'Unknown';
    const rlastName = args.rlast_name || 'Unknown';
    const rstreet = args.rstreet || 'Unknown';
    const rcity = args.rcity || 'Unknown';
    const rstate = args.rstate || 'Unknown';
    const rpostalCode = args.rpostalCode || 'Unknown';

    console.log(`Processing contact - First Name: ${firstName}, Last Name: ${lastName}, Street: ${street}, City: ${city}, State: ${state}, Postal Code: ${postalCode}, Country: ${country}`);
    try {
        var authToken = '';
        const pcmLoginApiUrl = 'https://apiqa.pcmintegrations.com/auth/marketing-cloud-login';
                
                console.log(`Checking if user exists: ${pcmLoginApiUrl}`);
                let encryptedMID = await encryptString_node(mid, CIPHER_KEY);
                const tokenresponse = await fetch(pcmLoginApiUrl, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        uniqueID: encryptedMID
                    })
                });

                const tokenresponseBody = await tokenresponse.json(); // Always try to parse the JSON body
                console.log('response:',tokenresponseBody);
                console.log('PCM API Response Status Code:', tokenresponse.status);
                if (tokenresponse.status === 200) {
                    // 1. 200 OK
                    authToken =tokenresponseBody.token;
                    console.log(tokenresponseBody);
                } else if (tokenresponse.status === 404) {
                    // 2. 404 Not Found
                    console.log(tokenresponseBody);
                }

        const requestBody = {
            "returnAddress": {
                "zipCode": rpostalCode,
                "state": rstate,
                "lastName": rlastName,
                "firstName": rfirstName,
                "city": rcity,
                "address2": "",
                "address": rstreet
            },
            "recipients": [
                {
                    "zipCode": postalCode,
                    "variables": [],
                    "state": state,
                    "lastName": lastName,
                    "firstName": firstName,
                    "extRefNbr": "", // Replace with your logic for external reference number
                    "city": city,
                    "address": street
                }
            ],
            "mailClass": "FirstClass",
            "globalDesignVariables": [],
            "designID": designId // Using the dynamic designId from args
        };
        console.log(JSON.stringify(requestBody));
        const response = await fetch('https://apiqa.pcmintegrations.com/order/postcard', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify(requestBody)
        });

        if (!response.ok) {
            console.error('Error sending postcard order:', response.status, response.statusText);
            try {
                const errorData = await response.json();
                console.error('Error details:', errorData);
                return res.status(response.status).json({ error: `Failed to send postcard order: ${response.statusText}`, details: errorData });
            } catch (e) {
                return res.status(response.status).json({ error: `Failed to send postcard order: ${response.statusText}` });
            }
        }
        const data = await response.json();
        res.json(data);
        console.log('Postcard order sent successfully');
    } catch (error) {
        console.error('Error sending postcard order:', error);
        res.status(500).json({ error: `Failed to send postcard order: ${error.message}` });
    }
    
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
app.post('/getDesigns',  async (req, res) => {
    console.log('getDesigns endpoint called');
    console.log('Request Headers:', JSON.stringify(req.headers));
    const { token } = req.body; 
    try {
        //const authToken = await getDesignToken();
        const response = await fetch('https://apiqa.pcmintegrations.com/design?perPage=1000', {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'Authorization': `Bearer ${token}`
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

// --- Endpoint to proxy DE request using frontend token ---
app.post('/api/verify', async (req, res) => {
    console.log('Received request for /api/verify');
    const { mid } = req.body; // Get token/URL from request body

    // Basic validation
    if (!mid) {
        return res.status(400).json({ error: 'Missing MID in request body.' });
    }

    
    try {

        const pcmLoginApiUrl = 'https://apiqa.pcmintegrations.com/auth/marketing-cloud-login';

        console.log(`Checking if user exists: ${pcmLoginApiUrl}`);
        let encryptedMID = await encryptString_node(mid, CIPHER_KEY);
        const response = await fetch(pcmLoginApiUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                uniqueID: encryptedMID
            })
        });

        const responseBody = await response.json(); // Always try to parse the JSON body
        console.log('response:',responseBody);
        console.log('PCM API Response Status Code:', response.status);
        if (response.status === 200) {
            // 1. 200 OK
            return res.status(200).json({
                success: true,
                existingUser: true,
                token: responseBody.token, // Assuming the token is directly in the responseBody
                JWT: responseBody.jwtSecret // Assuming the jwtSecret is directly in the responseBody
                                        // Or however you derive/access the JWT from the response
            });
        } else if (response.status === 404) {
            // 2. 404 Not Found
            return res.status(200).json({
                success: true,
                existingUser: false,
                // You might want to include the error message from the response if needed
                message: responseBody.error && responseBody.error.data && responseBody.error.data[0] ? responseBody.error.data[0].message : "Unable to locate account",
                errorCode: responseBody.error ? responseBody.error.code : 404
            });
        } else if (response.status === 500) {
            // 3. 500 Internal Server Error
            let errorMessage = "An unexpected error has occurred.";
            if (responseBody.error && responseBody.error.data && responseBody.error.data[0] && responseBody.error.data[0].message) {
                errorMessage = responseBody.error.data[0].message;
            }
            return res.status(500).json({
                success: false,
                message: errorMessage,
                errorCode: responseBody.error ? responseBody.error.code : 500
            });
        } else {
            // Handle other unexpected statuses
            let errorMessage = `Unexpected status code: ${response.status}`;
            if (responseBody.error && responseBody.error.message) {
                errorMessage = responseBody.error.message;
            } else if (responseBody.message) {
                errorMessage = responseBody.message;
            }
            return res.status(500).json({
                success: false,
                message: errorMessage,
                errorCode: response.status,
                details: responseBody // include the full body for debugging if desired
            });
        }
    } catch (error) {
        console.error('Error during design token retrieval:', error);
        return res.status(500).json({
            success: false,
            message: error.message || "A network error occurred or the response was not valid JSON.",
            errorCode: "NETWORK_OR_PARSE_ERROR" // Custom error code for this scenario
        });
    }
});




// --- Registration Endpoint (Server-Side) ---
app.post('/api/registration', async (req, res) => {
    console.log('Received request for /api/registration');
    
    // Destructure apiKey, apiSecret, AND jwtSecret from req.body
    const { apiKey, apiSecret, jwtSecret, mid } = req.body;

    // As per your previous request, explicit server-side validation for the presence of these
    // fields was removed, relying on client-side validation.
    // If any of these (apiKey, apiSecret, or now jwtSecret if deemed critical for PCM calls)
    // are missing, the respective PCM API calls will likely fail,
    // and that failure will be handled by the error checks below.

    try {
        // --- Call 1: Login to PCM API to get an auth token ---
        console.log('Registration Step 1: Calling PCM login API with provided credentials...');
        const loginApiUrl = 'https://apiqa.pcmintegrations.com/auth/login';
        
        const loginResponse = await fetch(loginApiUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                apiKey: apiKey,       // From req.body
                apiSecret: apiSecret  // From req.body
            })
        });

        let loginData;
        const loginResponseText = await loginResponse.text();
        try {
            loginData = JSON.parse(loginResponseText);
        } catch (e) {
            console.error(`PCM Login API response was not valid JSON. Status: ${loginResponse.status}, Body: ${loginResponseText}`);
            return res.status(502).json({
                success: false,
                error: 'Failed to process response from authentication service (non-JSON).',
                errorCode: 'PCM_LOGIN_BAD_RESPONSE'
            });
        }

        if (!loginResponse.ok) {
            console.error(`PCM Login API failed. Status: ${loginResponse.status}, Body:`, loginData);
            const statusCodeToClient = loginResponse.status >= 500 ? 502 : loginResponse.status;
            return res.status(statusCodeToClient).json({
                success: false,
                error: `Authentication failed with PCM service: ${loginData.message || loginResponse.statusText || 'Unknown authentication error'}`,
                errorCode: loginData.errorCode || `PCM_LOGIN_ERROR_${loginResponse.status}`,
                details: loginData
            });
        }

        const authToken = loginData.token;
        if (!authToken) {
            console.error('PCM Login API successful (2xx) but no token received. Body:', loginData);
            return res.status(500).json({
                success: false,
                error: 'Authentication successful but token was not provided by the service.',
                errorCode: 'PCM_LOGIN_NO_TOKEN'
            });
        }
        console.log('Registration Step 1: PCM Login successful. Token received.');

        // --- Call 2: Enable Marketing Cloud integration using the auth token ---
        console.log('Registration Step 2: Calling PCM enable Marketing Cloud API...');
        const enableMcApiUrl = 'https://apiqa.pcmintegrations.com/integration/enable-marketing-cloud';
        let encryptedMID = await encryptString_node(mid, CIPHER_KEY);
        // Construct the body for the second API call
        // Now using the jwtSecret received from the client's request body
        const enableMcBody = {
            "uniqueID": encryptedMID, // This remains hardcoded as per original spec
            "jwtSecret": jwtSecret // Using the jwtSecret from req.body
        };
        
        // Optional: If jwtSecret is absolutely mandatory for the PCM API and client might not send it
        // (even though client-side validation should catch it), you could add a specific check here:
        if (typeof jwtSecret === 'undefined' || jwtSecret === null || jwtSecret === '') {
             console.warn('Warning: jwtSecret for enableMcBody is missing or empty. PCM API might reject.');
             // Depending on PCM API's strictness, you might even return an error here:
             // return res.status(400).json({ success: false, error: 'jwtSecret is required for enabling Marketing Cloud integration.' });
        }


        const enableMcResponse = await fetch(enableMcApiUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify(enableMcBody)
        });

        let enableMcData;
        

        if (!enableMcResponse.ok) {
            const enableMcResponseText = await enableMcResponse.text();
            try {
                enableMcData = JSON.parse(enableMcResponseText);
            } catch (e) {
                console.error(`PCM Enable MC API response was not valid JSON. Status: ${enableMcResponse.status}, Body: ${enableMcResponseText}`);
                return res.status(502).json({
                    success: false,
                    error: 'Failed to process response from Marketing Cloud integration service (non-JSON).',
                    errorCode: 'PCM_ENABLE_MC_BAD_RESPONSE'
                });
            }
            console.error(`PCM Enable MC API failed. Status: ${enableMcResponse.status}, Body:`, enableMcData);
            const statusCodeToClient = enableMcResponse.status >= 500 ? 502 : enableMcResponse.status;
            return res.status(statusCodeToClient).json({
                success: false,
                error: `Failed to enable Marketing Cloud integration: ${enableMcData.message || enableMcResponse.statusText || 'Unknown integration error'}`,
                errorCode: enableMcData.errorCode || `PCM_ENABLE_MC_ERROR_${enableMcResponse.status}`,
                details: enableMcData
            });
        }

        console.log('Registration Step 2: PCM Enable Marketing Cloud successful.', enableMcData);

         // --- Call 3: Fetch Designs using the authToken from Call 1 ---
         console.log('Registration Step 3: Fetching designs...');
         const designsApiUrl = 'https://apiqa.pcmintegrations.com/design?perPage=1000';
         let designsData = null;
         let designsError = null; // To store any error message specifically from fetching designs
 
         try {
             const designsResponse = await fetch(designsApiUrl, {
                 method: 'GET',
                 headers: {
                     'Accept': 'application/json',
                     'Authorization': `Bearer ${authToken}` // Use the token from Call 1
                 }
             });
 
             const designsResponseText = await designsResponse.text();
             let parsedDesignsData; // Temporary variable for parsing
             try {
                 parsedDesignsData = JSON.parse(designsResponseText);
             } catch (e) {
                 console.error(`PCM Designs API response was not valid JSON. Status: ${designsResponse.status}, Body: ${designsResponseText}`);
                 if (!designsResponse.ok) { // If HTTP status was also an error
                     designsError = `Failed to fetch designs: Upstream API error (Status ${designsResponse.status}, non-JSON response).`;
                 } else { // HTTP status was OK, but body wasn't JSON (unexpected)
                     designsError = 'Failed to fetch designs: Upstream API response was not valid JSON despite an OK status.';
                 }
                 // designsData remains null
             }
 
             if (designsResponse.ok && !designsError) { // If HTTP status is OK and no parsing error occurred
                 designsData = parsedDesignsData; // Assign parsed data
                 console.log('Registration Step 3: Designs fetched successfully.');
             } else if (!designsError) { // HTTP status was not OK, but JSON might have error details
                 designsError = `Failed to fetch designs: ${parsedDesignsData.message || parsedDesignsData.error || designsResponse.statusText || 'Unknown error from designs API'}`;
                 console.error(`PCM Designs API failed. Status: ${designsResponse.status}, Parsed Body (if any):`, parsedDesignsData);
             }
             // If designsError was set by JSON parsing failure, it's already captured.
 
         } catch (fetchDesignsNetworkError) {
             // This catches network errors for the designs fetch call itself
             console.error('Network or other error during Fetch Designs call:', fetchDesignsNetworkError);
             designsError = `Failed to fetch designs due to a network or system error: ${fetchDesignsNetworkError.message}`;
         }
 
         // Send final success response to the client
         // The overall 'success' pertains to the primary registration (Steps 1 & 2)
         res.status(200).json({
             success: true, 
             message: 'Registration and Marketing Cloud integration setup completed.',
             registrationDetails: enableMcData, // Details from Call 2
             designsData: designsData,          // Actual designs data from Call 3 (or null if error)
             designsError: designsError         // Error message if Call 3 failed (or null if success)
         });

    } catch (error) {
        console.error('Error during /api/registration process:', error.message, error.stack);
        res.status(500).json({
            success: false,
            error: 'An internal server error occurred during the registration process.',
            errorCode: 'INTERNAL_SERVER_ERROR'
        });
    }
});
// ... rest of your server.js (static files, other routes, app.listen) ...

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});