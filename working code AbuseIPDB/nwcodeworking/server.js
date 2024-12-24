import express from 'express';
import bodyParser from 'body-parser';
import fetch from 'node-fetch';  // Import node-fetch

const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(express.static('public'));  // To serve static files (HTML)

const ABUSEIPDB_API_KEY = '7ed18310843445f21d48cda5ee0dbc2c2904e01a076a034b143a26dcad2879fa7399d4049bd9d7ab';  // Your AbuseIPDB API Key
const VIRUSTOTAL_API_KEY = '5abfb684330cf44a5d0c24c7cc616eb00dc8a9237ff5e86357b6caaf9cd094b7';  // Your VirusTotal API Key

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
    let response;

    // Check if it's an IP or a URL
    const ipUrl = `https://www.virustotal.com/api/v3/ip_addresses/${inputValue}`;  // For IP reputation
    const url = `https://www.virustotal.com/api/v3/urls/${Buffer.from(inputValue).toString('base64')}`; // For URL reputation

    // Check for URL or IP
    if (inputValue.includes('.')) {
        if (inputValue.startsWith("http")) {
            // URL: Base64 encode and check
            response = await fetch(url, {
                method: 'GET',
                headers: {
                    'x-apikey': VIRUSTOTAL_API_KEY
                }
            });
        } else {
            // IP: Directly query for the IP address
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

        let abuseIPDBResult = null;
        let virusTotalResult = null;

        if (isIpAddress) {
            // If it's an IP address, check both AbuseIPDB and VirusTotal
            abuseIPDBResult = await checkAbuseIPDB(inputValue);
            virusTotalResult = await checkVirusTotal(inputValue);  // Check VirusTotal for IP
        } else {
            // Otherwise, assume it's a URL and check VirusTotal
            virusTotalResult = await checkVirusTotal(inputValue);  // Check VirusTotal for URL
        }

        const formattedResult = {
            ...(abuseIPDBResult && {
                abuseIPDB: {
                    method: 'blacklist',
                    engine_name: 'AbuseIPDB',
                    category: abuseIPDBResult.data.abuseConfidenceScore > 50 ? 'malicious' : 'harmless',
                    result: abuseIPDBResult.data.abuseConfidenceScore > 50 ? 'malicious' : 'clean',
                    reputation: abuseIPDBResult.data.abuseConfidenceScore > 50 ? 'bad' : 'neutral',
                    reputation_score: abuseIPDBResult.data.abuseConfidenceScore,  // Use the confidence score as reputation score
                },
            }),
            ...(virusTotalResult && {
                virusTotal: {
                    method: 'blacklist',
                    engine_name: 'VirusTotal',
                    category: virusTotalResult.data.attributes.last_analysis_stats.malicious > 0 ? 'malicious' : 'harmless',
                    result: virusTotalResult.data.attributes.last_analysis_stats.malicious > 0 ? 'malware' : 'clean',
                    reputation: virusTotalResult.data.attributes.last_analysis_stats.malicious > 0 ? 'bad' : 'neutral',
                    reputation_score: virusTotalResult.data.attributes.last_analysis_stats.malicious,  // Use VirusTotal's malicious count as the reputation score
                },
            }),
        };

        return res.json(formattedResult);

    } catch (error) {
        console.error('Error checking reputation:', error);
        res.status(500).json({ error: error.message });
    }
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
