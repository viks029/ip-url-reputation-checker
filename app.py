from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# Replace with your actual API keys
VIRUSTOTAL_API_KEY = 'aa753d70076971f062ecc9f05f215a888477aac2d62f41addbd46f29c4783b9d'
ABUSEIPDB_API_KEY = '7ed18310843445f21d48cda5ee0dbc2c2904e01a076a034b143a26dcad2879fa7399d4049bd9d7ab'

@app.route('/check', methods=['POST'])
def check_reputation():
    data = request.json
    input_value = data.get('inputValue')

    # VirusTotal API Call
    vt_response = requests.get(
        f"https://www.virustotal.com/api/v3/domains/{input_value}",
        headers={"x-apikey": VIRUSTOTAL_API_KEY}
    )
    vt_result = vt_response.json()

    # AbuseIPDB API Call (if input is an IP)
    abuseipdb_result = {}
    if is_ip(input_value):  # Helper function to check if it's an IP
        abuseipdb_response = requests.get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={input_value}",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            }
        )
        abuseipdb_result = abuseipdb_response.json()

    return jsonify({
        "virustotal": vt_result,
        "abuseipdb": abuseipdb_result
    })

def is_ip(value):
    import re
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    return re.match(ip_pattern, value) is not None

if __name__ == '__main__':
    app.run(debug=True)
