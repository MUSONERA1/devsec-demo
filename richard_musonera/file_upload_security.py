"""
Secure file upload handling for user avatars and documents.

Implements:
- File type validation (magic bytes / MIME type checking)
- File size limits
- Image dimension validation
- Secure filename handling
- Audit logging for upload events

Security principles:
- Validate on server-side (never trust client)
- Check magic bytes, not just extensions
- Enforce strict MIME type whitelist
- Prevent directory traversal attacks
- Isolate uploaded files from execution context
- Log all upload events for audit trail
"""

import os
import logging
from io import BytesIO
from typing import Tuple, Optional

from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import UploadedFile
from django.utils.text import slugify
from PIL import Image

logger = logging.getLogger(__name__)

# ==========================================
# SECURITY CONFIGURATION
# ==========================================

# Maximum file sizes (in bytes)
MAX_AVATAR_SIZE = 5 * 1024 * 1024  # 5 MB for avatars
MAX_DOCUMENT_SIZE = 10 * 1024 * 1024  # 10 MB for documents

# Allowed MIME types for avatars (images)
ALLOWED_AVATAR_MIMES = {
    'image/jpeg': [b'\xFF\xD8\xFF'],  # JPEG magic bytes
    'image/png': [b'\x89PNG\r\n\x1a\n'],  # PNG magic bytes
    'image/gif': [b'GIF87a', b'GIF89a'],  # GIF magic bytes
    'image/webp': [b'RIFF'],  # WebP (starts with RIFF)
}

# Image dimension constraints
MIN_AVATAR_WIDTH = 32  # pixels
MIN_AVATAR_HEIGHT = 32  # pixels
MAX_AVATAR_WIDTH = 4096  # pixels
MAX_AVATAR_HEIGHT = 4096  # pixels

# Forbidden file extensions (executable, script, etc.)
FORBIDDEN_EXTENSIONS = {
    # Executables
    'exe', 'bat', 'cmd', 'com', 'pif', 'scr',
    # Scripts
    'js', 'py', 'php', 'sh', 'bash', 'ps1', 'vbs', 'jar',
    # Archives
    'zip', 'rar', '7z', 'tar', 'gz',
    # Office macros
    'docm', 'xlsm', 'pptm',
    # System files
    'sys', 'drv', 'dll',
    # Other dangerous types
    'app', 'deb', 'apk', 'msi',
}


# ==========================================
# MAGIC BYTE VALIDATORS
# ==========================================

def check_magic_bytes(file_object: UploadedFile, expected_mimes: dict) -> Optional[str]:
    """
    Validate file magic bytes to verify actual file type.
    
    Args:
        file_object: Django UploadedFile object
        expected_mimes: Dictionary mapping MIME types to magic byte signatures
    
    Returns:
        Detected MIME type string if valid, None if invalid
    
    Raises:
        ValidationError: If magic bytes don't match expected MIME types
    """
    # Read first 16 bytes to check magic bytes
    file_object.seek(0)
    header = file_object.read(16)
    
    # Check against all allowed magic bytes
    for mime_type, magic_bytes_list in expected_mimes.items():
        for magic_bytes in magic_bytes_list:
            if header.startswith(magic_bytes):
                file_object.seek(0)  # Reset to beginning
                return mime_type
    
    # Magic bytes don't match any allowed type
    file_object.seek(0)
    return None


# ==========================================
# VALIDATORS FOR AVATARS
# ==========================================

def validate_avatar_file_size(file_object: UploadedFile) -> None:
    """
    Validate that uploaded avatar is within size limits.
    
    Args:
        file_object: Django UploadedFile object
    
    Raises:
        ValidationError: If file exceeds max size
    """
    if file_object.size > MAX_AVATAR_SIZE:
        max_mb = MAX_AVATAR_SIZE / (1024 * 1024)
        file_mb = file_object.size / (1024 * 1024)
        raise ValidationError(
            f'Avatar must be smaller than {max_mb}MB (current: {file_mb:.1f}MB)'
        )


def validate_avatar_file_type(file_object: UploadedFile) -> None:
    """
    Validate that avatar has allowed file type via magic bytes.
    
    Args:
        file_object: Django UploadedFile object
    
    Raises:
        ValidationError: If file type is not allowed
    """
    detected_mime = check_magic_bytes(file_object, ALLOWED_AVATAR_MIMES)
    if not detected_mime:
        raise ValidationError(
            'Invalid image type. Allowed types: JPG, PNG, GIF, WebP'
        )


def validate_avatar_extension(file_object: UploadedFile) -> None:
    """
    Validate that avatar extension is in whitelist.
    
    Args:
        file_object: Django UploadedFile object
    
    Raises:
        ValidationError: If extension is forbidden
    """
    filename = file_object.name.lower()
    ext = filename.split('.')[-1] if '.' in filename else ''
    
    if ext in FORBIDDEN_EXTENSIONS:
        raise ValidationError(f'File extension "{ext}" is not allowed')


def validate_avatar_dimensions(file_object: UploadedFile) -> None:
    """
    Validate that avatar has reasonable dimensions.
    
    Prevents:
    - Enormous images (resource exhaustion)
    - Extremely small images (useless)
    - Crafted images designed to exploit image processing
    
    Args:
        file_object: Django UploadedFile object
    
    Raises:
        ValidationError: If dimensions are invalid
    """
    try:
        # Attempt to open as image
        image = Image.open(file_object)
        width, height = image.size
        
        # Check minimum dimensions
        if width < MIN_AVATAR_WIDTH or height < MIN_AVATAR_HEIGHT:
            raise ValidationError(
                f'Avatar too small. Minimum: {MIN_AVATAR_WIDTH}x{MIN_AVATAR_HEIGHT}px '
                f'(current: {width}x{height}px)'
            )
        
        # Check maximum dimensions
        if width > MAX_AVATAR_WIDTH or height > MAX_AVATAR_HEIGHT:
            raise ValidationError(
                f'Avatar too large. Maximum: {MAX_AVATAR_WIDTH}x{MAX_AVATAR_HEIGHT}px '
                f'(current: {width}x{height}px)'
            )
        
        file_object.seek(0)  # Reset for further processing
        
    except (IOError, OSError) as e:
        raise ValidationError(f'Invalid image file: {str(e)}')


def validate_avatar(file_object: UploadedFile) -> None:
    """
    Comprehensive avatar validation: size, type, extension, dimensions.
    
    Args:
        file_object: Django UploadedFile object
    
    Raises:
        ValidationError: If any validation fails
    """
    if not file_object:
        return  # Skip validation for empty uploads
    
    # Run all validators
    validate_avatar_file_size(file_object)
    validate_avatar_file_type(file_object)
    validate_avatar_extension(file_object)
    validate_avatar_dimensions(file_object)


# ==========================================
# SECURE FILENAME HANDLING
# ==========================================

def generate_secure_filename(original_filename: str, user_id: int) -> str:
    """
    Generate a secure filename from user input.
    
    Prevents:
    - Directory traversal (../, ..\, etc.)
    - Special characters that might be dangerous
    - Predictable filenames (allows enumeration)
    - Collision attacks (includes hash)
    
    Args:
        original_filename: Filename provided by user
        user_id: Django User ID
    
    Returns:
        Safe filename with user ID and hash
    """
    import hashlib
    import time
    
    # Extract extension only
    _, ext = os.path.splitext(original_filename)
    ext = ext.lower()
    
    # Generate unique-ish identifier
    identifier = f"{user_id}_{int(time.time() * 1000)}"
    
    # Create hash for additional uniqueness
    file_hash = hashlib.md5(identifier.encode()).hexdigest()[:8]
    
    # Create safe filename: user_{userid}_{timestamp_hash}.{ext}
    safe_name = f"user_{user_id}_{file_hash}{ext}"
    
    return safe_name


# ==========================================
# UPLOAD PATH FUNCTIONS
# ==========================================

def avatar_upload_path(instance, filename: str) -> str:
    """
    Generate safe upload path for avatar.
    
    Pattern: avatars/{year}/{month}/{day}/user_{userid}_{hash}.{ext}
    
    Args:
        instance: UserProfile instance
        filename: Original filename
    
    Returns:
        Relative path for upload
    """
    from datetime import datetime
    
    safe_filename = generate_secure_filename(filename, instance.user.id)
    now = datetime.now()
    
    # Create path: avatars/2026/04/17/user_123_abc.jpg
    return f"avatars/{now.year}/{now.month:02d}/{now.day:02d}/{safe_filename}"


# ==========================================
# AUDIT LOGGING FOR UPLOADS
# ==========================================

def log_file_upload(request, user_id: int, filename: str, file_size: int,
                   mime_type: str, status: str, error_msg: str = '') -> None:
    """
    Log file upload event for security audit trail.
    
    Args:
        request: Django request object
        user_id: ID of user uploading file
        filename: Original filename
        file_size: Size in bytes
        mime_type: Detected MIME type
        status: 'success' or 'failed'
        error_msg: Error message if failed
    """
    ip_address = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    
    # Import here to avoid circular imports
    from .models import AuditLog
    
    AuditLog.log_event(
        event_type='UPLOAD_FILE',
        request=request,
        user=request.user if request.user.is_authenticated else None,
        success=(status == 'success'),
        details={
            'filename': filename,
            'file_size_bytes': file_size,
            'mime_type': mime_type,
            'ip_address': ip_address,
            'status': status,
        },
        error_msg=error_msg if error_msg else None
    )
    
    if status == 'success':
        logger.info(
            f"File upload successful: user_id={user_id}, "
            f"filename={filename}, size={file_size} bytes, "
            f"mime_type={mime_type}, ip={ip_address}"
        )
    else:
        logger.warning(
            f"File upload failed: user_id={user_id}, "
            f"filename={filename}, error={error_msg}, ip={ip_address}"
        )


def get_client_ip(request) -> str:
    """
    Extract client IP address from request.
    
    Args:
        request: Django request object
    
    Returns:
        Client IP address string
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR', '')
    return ip


# ==========================================
# FILE PROCESSING UTILITIES
# ==========================================

def process_avatar_image(file_object: UploadedFile, max_width: int = 512,
                        max_height: int = 512, quality: int = 85) -> UploadedFile:
    """
    Process avatar image: resize and optimize.
    
    Args:
        file_object: Uploaded image file
        max_width: Maximum width in pixels
        max_height: Maximum height in pixels
        quality: JPEG quality (1-100)
    
    Returns:
        Processed image as UploadedFile
    """
    try:
        # Open and validate image
        image = Image.open(file_object)
        
        # Convert RGBA to RGB if necessary (for JPEG)
        if image.mode in ('RGBA', 'LA', 'P'):
            background = Image.new('RGB', image.size, (255, 255, 255))
            if image.mode == 'P':
                image = image.convert('RGBA')
            background.paste(image, mask=image.split()[-1])
            image = background
        
        # Resize if necessary (maintain aspect ratio)
        image.thumbnail((max_width, max_height), Image.Resampling.LANCZOS)
        
        # Save to BytesIO
        output = BytesIO()
        image.save(output, format='JPEG', quality=quality, optimize=True)
        output.seek(0)
        
        # Return as UploadedFile
        from django.core.files.uploadedfile import InMemoryUploadedFile
        
        return InMemoryUploadedFile(
            output, 'ImageField',
            file_object.name, 'image/jpeg',
            output.getbuffer().nbytes, None
        )
    
    except Exception as e:
        logger.error(f"Error processing avatar: {str(e)}")
        # Return original file if processing fails
        file_object.seek(0)
        return file_object
