
"""Extract text from screenshots and analyze them for potential scams."""

import os
from io import BytesIO
from pathlib import Path

import pytesseract
from PIL import Image, UnidentifiedImageError
from PIL.Image import DecompressionBombError as ImageDecompressionBombError

from message_scanner import analyze_message


# Configure Tesseract OCR.
# On deployment platforms, set TESSERACT_CMD if needed.
tesseract_cmd = os.getenv("TESSERACT_CMD")

if tesseract_cmd:
    pytesseract.pytesseract.tesseract_cmd = tesseract_cmd
else:
    windows_tesseract = Path(
        r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    )
    if windows_tesseract.exists():
        pytesseract.pytesseract.tesseract_cmd = str(windows_tesseract)


# Upload and image-processing limits.
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_IMAGE_PIXELS = 20_000_000
ALLOWED_FORMATS = {"PNG", "JPEG", "WEBP", "BMP"}


def analyze_screenshot(file_storage):
    """Extract screenshot text and analyze it for potential scams."""

    # 1. Validate that a file was uploaded.
    if file_storage is None or not file_storage.filename:
        raise ValueError("Please select an image to upload.")

    # 2. Read a limited amount of data to prevent oversized uploads.
    raw_data = file_storage.stream.read(MAX_FILE_SIZE + 1)

    if not raw_data:
        raise ValueError("The uploaded image is empty.")

    if len(raw_data) > MAX_FILE_SIZE:
        raise ValueError("Image size must not exceed 5 MB.")

    # 3. Validate the image before processing it.
    try:
        with Image.open(BytesIO(raw_data)) as source:
            image_format = source.format

            if image_format not in ALLOWED_FORMATS:
                raise ValueError(
                    "Unsupported image format. Use PNG, JPEG, WEBP, or BMP."
                )

            width, height = source.size

            if width <= 0 or height <= 0:
                raise ValueError("The uploaded image has invalid dimensions.")

            if width * height > MAX_IMAGE_PIXELS:
                raise ValueError(
                    "Image dimensions are too large. "
                    "Use a smaller screenshot."
                )

            # Verify image integrity before decoding it fully.
            source.verify()

        # Reopen the verified image for actual processing.
        with Image.open(BytesIO(raw_data)) as source:
            image = ImageOps.exif_transpose(source).convert("RGB")
            image.load()

    except ImageDecompressionBombError as exc:
        raise ValueError(
            "This image is too large to process safely. "
            "Use a smaller screenshot."
        ) from exc

    except (UnidentifiedImageError, OSError) as exc:
        raise ValueError(
            "The uploaded file is not a valid supported image."
        ) from exc

    # 4. Extract text using OCR with a timeout.
    try:
        extracted_text = pytesseract.image_to_string(
            image,
            lang="eng",
            timeout=15,
        ).strip()

    except pytesseract.TesseractNotFoundError as exc:
        raise RuntimeError(
            "OCR is unavailable. Check the Tesseract installation."
        ) from exc

    except RuntimeError as exc:
        raise RuntimeError(
            "OCR could not finish. Try a smaller or clearer screenshot."
        ) from exc

    # 5. Reject screenshots with no readable text.
    if not extracted_text:
        raise ValueError(
            "No readable text was found. Try a clearer screenshot."
        )

    # 6. Analyze the extracted text using the existing message scanner.
    result = analyze_message(extracted_text)

    # 7. Return the analysis and its limitations.
    return {
        "extracted_text": extracted_text,
        "analysis": result,
        "limitations": (
            "OCR can misread text. Scam detection is heuristic and cannot "
            "guarantee that a message is safe or fraudulent."
        ),
    }
