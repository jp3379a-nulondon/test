
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

# --- Configuration -----------------------------------------------------------

load_dotenv()

API_KEY = os.getenv("API_KEY")
if not API_KEY:
    # Fail fast with a clear message instead of a confusing API error later.
    raise RuntimeError("API_KEY is not set. Add it to your .env file.")

VT_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"
ALLOWED_ORIGINS = {
    "http://127.0.0.1:5500",                 # local Live Server
    "https://jp3379a-nulondon.github.io",    # GitHub Pages (origin only!)
}
REQUEST_TIMEOUT = 6  # seconds

HEADERS = {
    "Accept": "application/json",
    "x-apikey": API_KEY,
}

app = Flask(__name__)


# --- CORS --------------------------------------------------------------------

@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    return response


# --- Helpers -----------------------------------------------------------------

def is_valid_ip(ip_address):
    """Return True if the string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def fetch_ip_data(ip_address):
    """Call VirusTotal and return the parsed JSON.

    Raises requests.HTTPError on a non-2xx response and
    requests.RequestException on connection/timeout problems, so the
    caller can handle failures in one place.
    """
    response = requests.get(
        f"{VT_BASE_URL}/{ip_address}",
        headers=HEADERS,
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def extract_stats(ip_address, ip_data):
    """Pull the analysis summary out of the VirusTotal response.

    Raises KeyError if the expected fields are missing.
    """
    stats = ip_data["data"]["attributes"]["last_analysis_stats"]
    return {
        "ip_address": ip_address,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "undetected": stats.get("undetected", 0),
        "harmless": stats.get("harmless", 0),
    }


def error_response(message, status):
    """Build a consistent JSON error response."""
    return jsonify({"success": False, "error": message}), status


# --- Routes ------------------------------------------------------------------

@app.route("/api/ip-reputation", methods=["POST", "OPTIONS"])
def ip_reputation():
    if request.method == "OPTIONS":
        return "", 204

    # silent=True returns None instead of raising on a missing/invalid body.
    data = request.get_json(silent=True)
    if not data or not data.get("ip_address"):
        return error_response("No IP address was provided.", 400)

    user_ip = data["ip_address"].strip()
    if not is_valid_ip(user_ip):
        return error_response(
            "Invalid IP address. Enter a correctly formatted IP address.", 400
        )

    try:
        ip_data = fetch_ip_data(user_ip)
        results = extract_stats(user_ip, ip_data)
    except requests.HTTPError as error:
        status = error.response.status_code
        return error_response(
            f"VirusTotal request failed ({status}). "
            "Check your API key, the IP, or your request limit.",
            502,
        )
    except (KeyError, ValueError):
        return error_response(
            "Could not find analysis data in the VirusTotal response.", 502
        )
    except requests.RequestException as error:
        return error_response(f"Could not reach VirusTotal: {error}", 502)

    return jsonify({"success": True, "results": results})


if __name__ == "__main__":
    app.run()  # add debug=True only for local development
