import express from 'express';  // Use import for ES modules
import bodyParser from 'body-parser';
import fetch from 'node-fetch';  // ES module import

const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(express.static('public'));  // To serve static files (HTML)

const ABUSEIPDB_API_KEY = '7ed18310843445f21d48cda5ee0dbc2c2904e01a076a034b143a26dcad2879fa7399d4049bd9d7ab';  // Your AbuseIPDB API Key

app.post('/check', async (req, res) => {
    const inputValue = req.body.inputValue;

    try {
        // Check if the input is a valid IP address (AbuseIPDB works with IPs)
        const ipRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

        if (!ipRegex.test(inputValue)) {
            return res.status(400).json({ error: 'Please enter a valid IP address' });
        }

        // Make the request to AbuseIPDB API
        const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${inputValue}`, {
            method: 'GET',
            headers: {
                'Key': ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }
        });

        if (!response.ok) {
            const errorResponse = await response.text();
            console.error(`Error from AbuseIPDB API: ${response.status} - ${response.statusText}`);
            console.error('Response Body:', errorResponse);
            throw new Error(`Error from AbuseIPDB API: ${response.statusText}`);
        }

        const data = await response.json();
        res.json(data);  // Send back the response to the frontend
    } catch (error) {
        console.error('Error checking reputation:', error);  // Log the full error
        res.status(500).json({ error: error.message });  // Send the error message to the frontend
    }
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
