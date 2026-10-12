from screenshot_scanner import analyze_screenshot
from flask import Flask, jsonify, render_template, request
from dotenv import load_dotenv

from scanner import analyze_url
from threat_intel import check_threat
from message_scanner import analyze_message
load_dotenv()


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"],
    storage_uri="memory://",
)


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    response.headers["Content-Security-Policy"] = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "style-src-attr 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "object-src 'none'"
)
    return response

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
@limiter.limit("10 per minute")
def scan_url():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request."}), 400

    url = data.get("url")

    if not isinstance(url, str):
        return jsonify({"error": "Please enter a valid URL."}), 400

    try:
        result = analyze_url(url)

        # Check the normalized URL returned by the scanner.
        threat_result = check_threat(result["url"])
        result["threat_intelligence"] = threat_result

        # Only a confirmed match increases the score.
        if threat_result["status"] == "threat_detected":
            result["risk_score"] = max(result["risk_score"], 80)
            result["risk_level"] = "High"
            result["findings"].append(
                "Google Safe Browsing reported a threat match."
            )
            result["recommendation"] = (
                "Do not visit this URL. A threat match was reported."
            )

        return jsonify(result), 200

    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

@app.route("/api/analyze-message", methods=["POST"])
@limiter.limit("10 per minute")
def analyze_message_route():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request."}), 400

    message = data.get("message")

    if not isinstance(message, str):
        return jsonify({"error": "Please enter a message."}), 400

    try:
        result = analyze_message(message)
        return jsonify(result), 200
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
@app.errorhandler(413)
def request_too_large(error):
    return jsonify({"error": "Request is too large."}), 413

@app.route("/api/analyze-screenshot", methods=["POST"])
@limiter.limit("5 per minute")
def analyze_screenshot_route():
    uploaded_file = request.files.get("screenshot")

    try:
        result = analyze_screenshot(uploaded_file)
        return jsonify(result), 200

    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    except RuntimeError as exc:
        app.logger.error("Screenshot OCR unavailable: %s", exc)
        return jsonify({"error": str(exc)}), 503

@app.errorhandler(500)
def internal_server_error(error):
    app.logger.error("Internal server error: %s", error)
    return jsonify({
        "error": "An unexpected server error occurred. Please try again."
    }), 500
if __name__ == "__main__":
    app.run(debug=False)