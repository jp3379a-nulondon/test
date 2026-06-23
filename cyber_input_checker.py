
import ipaddress
from flask import Flask, request, jsonify
from flask_cors import CORS
import gunicorn # Package used to run app on render (external server)
import os
from dotenv import load_dotenv # Loads .env values into environment variables
import requests


"""
This code defines a Flask web application that provides an API endpoint for checking the reputation of an IP address using the VirusTotal API. 
The application validates the input IP address, retrieves information from the VirusTotal API, and returns a JSON response with the analysis results. 
It also includes error handling for various scenarios such as invalid input, API request failures, and missing data in the API response.

Need to install:
- Flask: `pip install Flask`
- Requests: `pip install requests`
- Python-dotenv: `pip install python-dotenv` (to load environment variables from a .env file)

"""


# Load API key from .env file.
load_dotenv()

# This creates a Flask application instance.
app = Flask(__name__) 

# Creating a variable to store the API key from the .env file.
API_KEY = os.getenv("API_KEY")

# Define the headers for the API request to VirusTotal, including the API key for authentication.
headers = {
    "Accept": "application/json",
    "x-apikey": API_KEY
}


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "http://127.0.0.1:5500"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    return response


def validate_ip(ip_address):
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def get_ip_information(ip_address):
    api_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"

    try:
        api_response = requests.get(api_url, headers=headers, timeout=6)

        if api_response.status_code == 200: # Code 200 indicates a successful request
            return api_response.json()

        return {
            "error": f"API request failed with status code {api_response.status_code}. Check API key, URL, or request limit."
        }

    except requests.exceptions.RequestException as error:
        return {
            "error": f"API URL or connection failed. Details: {error}"
        }


def extract_required_results(ip_address, ip_data):
    try:
        stats = ip_data["data"]["attributes"]["last_analysis_stats"]

        return {
            "ip_address": ip_address,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            #"test": stats.get("test", 0)
        }

    except KeyError as error:
        return {
            "error": f"Analysis data was not found in the API response. Missing field: {error}"
        }


@app.route("/api/ip-reputation", methods=["POST", "OPTIONS"])
def ip_reputation():
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json() # Get the JSON data from the request body

    """
    if not data or "ip_address" not in data:
        return jsonify({
            "success": False,
            "error": "No IP address was provided."
        }), 400
        """

    user_ip = data["ip_address"].strip()

    if not validate_ip(user_ip):
        return jsonify({
            "success": False,
            "error": "Invalid IP address. Enter a correctly formatted IP address."
        }), 400

    ip_data = get_ip_information(user_ip)

    if "error" in ip_data:
        return jsonify({
            "success": False,
            "error": ip_data["error"]
        }), 502

    filtered_results = extract_required_results(user_ip, ip_data)


    if "error" in filtered_results:
        return jsonify({
            "success": False,
            "error": filtered_results["error"]
        }), 500

    return jsonify({
        "success": True,
        "results": filtered_results
    })


if __name__ == "__main__":
    app.run() #(debug=True)
