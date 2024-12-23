// Function to check IP reputation from AbuseIPDB
async function checkIPReputation(ip) {
    try {
        const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
            method: 'GET',
            headers: {
                'Key': '7ed18310843445f21d48cda5ee0dbc2c2904e01a076a034b143a26dcad2879fa7399d4049bd9d7ab',  // Your AbuseIPDB API key
                'Accept': 'application/json'
            }
        });

        const data = await response.json();
        displayIPResult(data);
    } catch (error) {
        console.error('Error checking IP reputation from AbuseIPDB:', error);
        document.getElementById('result').innerHTML = 'Error checking IP reputation from AbuseIPDB.';
    }
}

// Function to check URL reputation from VirusTotal
async function checkURLReputation(url) {
    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/urls/${encodeURIComponent(url)}`, {
            method: 'GET',
            headers: {
                'x-apikey': 'aa753d70076971f062ecc9f05f215a888477aac2d62f41addbd46f29c4783b9d'  // Your VirusTotal API key
            }
        });

        const data = await response.json();
        displayURLResult(data);
    } catch (error) {
        console.error('Error checking URL reputation from VirusTotal:', error);
        document.getElementById('url-result').innerHTML = 'Error checking URL reputation from VirusTotal.';
    }
}

// Function to display IP result
function displayIPResult(data) {
    if (data && data.data) {
        const ipInfo = data.data.attributes;
        let resultHTML = `
            <h3>AbuseIPDB Results:</h3>
            <p><strong>IP Address:</strong> ${ipInfo.ipAddress}</p>
            <p><strong>Reputation:</strong> ${ipInfo.isPublic ? 'Public' : 'Private'}</p>
            <p><strong>Abuse Confidence Score:</strong> ${ipInfo.abuseConfidenceScore}</p>
            <p><strong>Reported Abuse Count:</strong> ${ipInfo.reportedAbuseCount}</p>
        `;
        document.getElementById('result').innerHTML = resultHTML;
    } else {
        document.getElementById('result').innerHTML = 'No data found for this IP.';
    }
}

// Function to display URL result
function displayURLResult(data) {
    if (data && data.data) {
        const urlInfo = data.data.attributes.last_analysis_stats;
        let resultHTML = `
            <h3>VirusTotal URL Analysis:</h3>
            <p><strong>URL:</strong> ${data.data.id}</p>
            <p><strong>Malicious Detections:</strong> ${urlInfo.malicious}</p>
            <p><strong>Suspicious Detections:</strong> ${urlInfo.suspicious}</p>
            <p><strong>Harmless Detections:</strong> ${urlInfo.harmless}</p>
        `;
        document.getElementById('url-result').innerHTML = resultHTML;
    } else {
        document.getElementById('url-result').innerHTML = 'No data found for this URL.';
    }
}

// Function to handle the form submission for IP or URL
function handleSubmit() {
    const inputValue = document.getElementById('inputValue').value.trim();

    // If input is an IP address
    if (isValidIP(inputValue)) {
        checkIPReputation(inputValue);
        document.getElementById('url-result').innerHTML = '';  // Clear URL result panel
    }
    // If input is a URL
    else if (isValidURL(inputValue)) {
        checkURLReputation(inputValue);
        document.getElementById('result').innerHTML = '';  // Clear IP result panel
    } else {
        alert('Please enter a valid IP address or URL.');
    }
}

// Function to validate if input is a valid IP address
function isValidIP(ip) {
    const ipPattern = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipPattern.test(ip);
}

// Function to validate if input is a valid URL
function isValidURL(url) {
    const urlPattern = /^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$/i;
    return urlPattern.test(url);
}
