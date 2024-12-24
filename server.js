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
    const base64Url = Buffer.from(inputValue).toString('base64'); // Base64 encode the URL for VirusTotal
    const url = `https://www.virustotal.com/api/v3/urls/${base64Url}`; // For URL reputation

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
        // Regular expression to check if the input is a valid URL (including http, https, and others)
        const urlRegex = /^(ftp|http|https):\/\/[^ "]+$/;

        const isUrl = urlRegex.test(inputValue);
        const ipRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const isIpAddress = ipRegex.test(inputValue);

        let abuseIPDBResult = null;
        let virusTotalResult = null;

        if (isIpAddress) {
            // If it's an IP address, check both AbuseIPDB and VirusTotal
            abuseIPDBResult = await checkAbuseIPDB(inputValue);
            virusTotalResult = await checkVirusTotal(inputValue);
        } else if (isUrl) {
            // Otherwise, assume it's a URL and check VirusTotal
            virusTotalResult = await checkVirusTotal(inputValue);
        } else {
            throw new Error('Invalid input. Please provide a valid IP address or URL.');
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
