# LinkDisc

**Detect suspicious URLs, scam messages, and potential threats in screenshots.**

LinkDisc is a web-based security tool that analyzes links, message text, and screenshot text to identify potential phishing attempts and scam indicators.

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

## Run Locally

### 1. Clone the repository

```bash
git clone https://github.com/shriram-io/LinkDisc.git
cd LinkDisc
```

### 2. Create a virtual environment

Windows:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root:

```text
SAFE_BROWSING_API_KEY=your_google_safe_browsing_api_key
```

The API key is optional for running the application, but Google Safe Browsing checks require a valid configured key.

**Never commit your `.env` file or publish API keys.**

### 5. Install Tesseract OCR

Screenshot analysis requires the Tesseract OCR engine to be installed separately.

On Windows, install Tesseract and configure `TESSERACT_CMD` if it is not installed at the default path:

```text
TESSERACT_CMD=C:\Program Files\Tesseract-OCR\tesseract.exe
```

### 6. Start the application

```powershell
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

## Run Tests

```powershell
python -m pytest -q
```

## Security and Limitations

- Results are heuristic assessments, not guarantees that a URL or message is safe or fraudulent.
- OCR may misread text in screenshots.
- Threat intelligence depends on API configuration and service availability.
- Do not upload private, confidential, or sensitive information.
- Rate-limit storage is currently in memory; production deployments with multiple workers should use an appropriate shared storage backend.
- Configure secrets through your hosting provider's environment-variable settings when deploying.

## Project Status

The application has been tested locally. Public deployment and production behavior must be verified separately.

## License

No license has been specified yet. Check the repository's licensing before reusing or distributing this project.
