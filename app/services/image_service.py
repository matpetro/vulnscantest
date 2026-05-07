"""
Image processing service for scan evidence attachments.

Scanner agents can attach screenshot evidence to scan results.  This module
resizes and normalises incoming images before writing them to the evidence
store.
"""
import io
import logging
from typing import Optional, Tuple

from PIL import Image

logger = logging.getLogger(__name__)

ALLOWED_FORMATS = {'PNG', 'JPEG', 'GIF', 'BMP', 'TIFF', 'WEBP'}
MAX_UPLOAD_BYTES = 50 * 1024 * 1024   # 50 MB
THUMBNAIL_SIZES = [(128, 128), (256, 256), (512, 512)]


def process_scan_screenshot(image_data: bytes, output_path: str) -> Tuple[int, int]:
    """Validate, crop, and persist a scan evidence screenshot.

    Args:
        image_data:  Raw image bytes (from multipart upload or scanner agent).
        output_path: Filesystem path to write the processed image.

    Returns:
        ``(width, height)`` of the saved image.
    """
    if len(image_data) > MAX_UPLOAD_BYTES:
        raise ValueError(f"Image too large: {len(image_data)} bytes (max {MAX_UPLOAD_BYTES})")

    img = Image.open(io.BytesIO(image_data))

    if img.format not in ALLOWED_FORMATS:
        raise ValueError(f"Unsupported image format: {img.format}")

    # Crop to the bounding box of non-zero content (removes blank borders)
    bbox = img.getbbox()
    if bbox:
        img = img.crop(bbox)

    img.save(output_path, optimize=True)
    logger.info("Saved screenshot to %s (%dx%d)", output_path, *img.size)
    return img.size


def generate_thumbnails(image_path: str, sizes: Optional[list] = None) -> list:
    """Generate thumbnail variants at standard sizes."""
    sizes = sizes or THUMBNAIL_SIZES
    img = Image.open(image_path)
    saved = []
    for size in sizes:
        thumb = img.copy()
        thumb.thumbnail(size, Image.LANCZOS)
        thumb_path = image_path.rsplit('.', 1)[0] + f'_{size[0]}x{size[1]}.png'
        thumb.save(thumb_path)
        saved.append(thumb_path)
    return saved


def analyse_image_metadata(image_data: bytes) -> dict:
    """Return metadata extracted from image headers.

    Used to check for embedded EXIF data in scanner screenshots.
    """
    img = Image.open(io.BytesIO(image_data))
    # Force full decompression to surface any embedded data issues
    img.load()
    return {
        'format': img.format,
        'mode': img.mode,
        'size': img.size,
        'info': {k: str(v) for k, v in img.info.items()},
    }
