
# LinkDisc

**Detect suspicious URLs, scam messages, and potential threats in screenshots.**

LinkDisc is a web-based security tool that analyzes links, message text, and screenshot text to identify potential phishing attempts and scam indicators.

**Live Demo:** https://linkdisc.onrender.com  
**GitHub Repository:** https://github.com/shriram-io/LinkDisc

## Features

- **URL Scanner:** Examines URLs for suspicious patterns and risk indicators.
- **Message Analyzer:** Detects common scam signals in text messages.
- **Screenshot Analyzer:** Extracts text from supported images using OCR and analyzes the extracted message.
- **Threat Intelligence:** Checks URLs against Google Safe Browsing when the API is configured.
- **Input Validation:** Rejects invalid requests and unsupported uploads.
- **Security Controls:** Includes request-size limits, rate limiting, and security response headers.

## Technology Stack

- Python
- Flask
- Pillow
- Tesseract OCR
- Google Safe Browsing API
- Flask-Limiter
- Pytest
- HTML, CSS, and JavaScript

## Run Locally

### 1. Clone the repository

```bash
git clone https://github.com/shriram-io/LinkDisc.git
cd LinkDisc
```

### 2. Create a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root if your application is configured to load it:

```text
SAFE_BROWSING_API_KEY=your_google_safe_browsing_api_key
```

The API key is optional for running the application, but Google Safe Browsing checks require a valid configured key.

**Never commit your `.env` file or publish API keys.**

### 5. Install Tesseract OCR

Screenshot analysis requires the Tesseract OCR engine to be installed separately.

If Tesseract is not detected automatically, configure its executable path using the setting supported by your application. For example:

```text
TESSERACT_CMD=C:\Program Files\Tesseract-OCR\tesseract.exe
```

### 6. Start the application

```powershell
python app.py
```

Open http://127.0.0.1:5000 in your browser.

## Run Tests

```powershell
python -m pytest -v
```

The latest reported test run completed with **55 passing tests**.

## Security and Limitations

- Results are heuristic assessments, not guarantees that a URL or message is safe or fraudulent.
- OCR may misread text in screenshots.
- Threat intelligence depends on API configuration and service availability.
- Avoid uploading private, confidential, or sensitive information.
- Rate-limit storage is currently in memory; production deployments with multiple workers may require shared storage.
- Automated tests do not guarantee that every real-world scam will be detected.

## Project Status

- Public repository available on GitHub.
- Public demo deployed on Render.
- URL, message, and screenshot scanners manually verified on the deployed website.
- Latest reported automated test run: 55 passed.

## License

No license has been specified yet. Check the repository for a license file before reusing or redistributing this project.
