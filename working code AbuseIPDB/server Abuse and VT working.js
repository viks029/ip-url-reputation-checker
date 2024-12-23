import express from 'express';
import bodyParser from 'body-parser';
import fetch from 'node-fetch';  // Import node-fetch
const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(express.static('public'));  // To serve static files (HTML)

const ABUSEIPDB_API_KEY = '7ed18310843445f21d48cda5ee0dbc2c2904e01a076a034b143a26dcad2879fa7399d4049bd9d7ab';  // Your AbuseIPDB API Key
const VIRUSTOTAL_API_KEY = 'aa753d70076971f062ecc9f05f215a888477aac2d62f41addbd46f29c4783b9d';  // Your VirusTotal API Key

// Helper function to check IP using AbuseIPDB
async function checkAbuseIPDB(ip) {
    const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
        method: 'GET',
        headers: {
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        }
    });
    if (!response.ok) throw new Error(`Error from AbuseIPDB API: ${response.statusText}`);
    return await response.json();
}

// Helper function to check URL/IP using VirusTotal
async function checkVirusTotal(inputValue) {
    const ipUrl = `https://www.virustotal.com/api/v3/ip_addresses/${inputValue}`;  // For IP reputation
    
    // For URL, base64 encode the URL before using in the VirusTotal API request
    const url = `https://www.virustotal.com/api/v3/urls/${Buffer.from(inputValue).toString('base64')}`; // For URL reputation

    let response;
    if (inputValue.includes('.')) {  // Check if it's a URL or an IP
        if (inputValue.startsWith("http")) {
            response = await fetch(url, {
                method: 'GET',
                headers: {
                    'x-apikey': VIRUSTOTAL_API_KEY
                }
            });
        } else {
            response = await fetch(ipUrl, {
                method: 'GET',
                headers: {
                    'x-apikey': VIRUSTOTAL_API_KEY
                }
            });
        }
    }

    if (!response.ok) throw new Error(`Error from VirusTotal API: ${response.statusText}`);
    return await response.json();
}

app.post('/check', async (req, res) => {
    const inputValue = req.body.inputValue;

    try {
        // Check if the input is a valid IP address (AbuseIPDB works with IPs)
        const ipRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const isIpAddress = ipRegex.test(inputValue);

        if (isIpAddress) {
            // If it's an IP address, check both AbuseIPDB and VirusTotal
            const abuseIPDBResult = await checkAbuseIPDB(inputValue);
            const virusTotalResult = await checkVirusTotal(inputValue);
            return res.json({ abuseIPDB: abuseIPDBResult, virusTotal: virusTotalResult });
        } else {
            // Otherwise, assume it's a URL and check VirusTotal
            const virusTotalResult = await checkVirusTotal(inputValue);
            return res.json({ virusTotal: virusTotalResult });
        }

    } catch (error) {
        console.error('Error checking reputation:', error);  // Log the full error
        res.status(500).json({ error: error.message });  // Send the error message to the frontend
    }
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
