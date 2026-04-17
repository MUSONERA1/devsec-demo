# File Upload Security Guide

## Overview

This guide documents the secure file upload implementation for user avatars and profile pictures in the DevSecDemo application. The implementation follows OWASP security principles and includes comprehensive validation, audit logging, and access controls.

## Security Principles

### 1. **Server-Side Validation (Never Trust Client)**

All file validation occurs on the server, regardless of client-side checks. The application does not rely on:
- Browser file type filtering
- Client-side MIME type detection
- User-provided file extensions

### 2. **Magic Byte Validation**

Files are validated by examining their actual content (magic bytes), not file extensions. This prevents attackers from bypassing validation by renaming dangerous files.

**Supported Image Formats:**
- **JPEG**: Signature `FF D8 FF` (appears in all JPEG files)
- **PNG**: Signature `89 50 4E 47 0A 1A 0A` ("89PNG\r\n\x1a\n")
- **GIF**: Signature `47 49 46 38` ("GIF87a" or "GIF89a")
- **WebP**: Signature `52 49 46 46` ("RIFF" format marker)

**Example Attack Prevented:**
```
Attack: User uploads "dangerous.exe" but renames to "avatar.jpg"
Defense: Magic byte check reads first 16 bytes
Result: Detects actual EXE signature, rejects upload
```

### 3. **File Size Constraints**

Enforces strict limits to prevent resource exhaustion:

- **Avatar Images**: Maximum 5 MB
- **Document Uploads**: Maximum 10 MB

Size validation occurs at both:
1. Form field level (clean_profile_picture method)
2. Validator function level (validate_avatar_file_size)

### 4. **Dangerous Extension Blacklist**

30+ dangerous file extensions are explicitly blocked, including:

**Executable/Script Types:**
- exe, bat, cmd, com, pif, scr, vbs, js, py, rb, sh, zsh, bash, pl

**Compressed Archives:**
- zip, rar, 7z, tar, gz, tar.gz, iso, dmg

**System/Configuration Files:**
- dll, so, sys, ini, cfg, conf, config, xml

**Other Dangerous Types:**
- app, apk, jar, msi, pkg, deb

**Why Blacklist?**
- Prevents execution if files accessed directly
- Provides defense-in-depth alongside magic bytes
- Catches edge cases and uncommon dangerous formats

### 5. **Image Dimension Validation**

Prevents resource exhaustion attacks through specially crafted images:

- **Minimum**: 32 × 32 pixels (prevents tiny/dot images)
- **Maximum**: 4096 × 4096 pixels (prevents memory bomb attacks)

This prevents attacks like:
```
Attack: Zip bomb disguised as image with extreme dimensions
Defense: Image is loaded, actual dimensions read
Result: If <32px or >4096px → rejected
```

### 6. **Secure Filename Generation**

Uploaded files are renamed to prevent directory traversal and information leakage:

**Pattern:** `user_{userid}_{timestamp_hash}.{extension}`

**Examples:**
```
Original: ../../../etc/passwd.jpg
Stored as: user_42_1704067200_a3f2.jpg

Original: my profile photo.jpg
Stored as: user_42_1704067200_b7e1.jpg

Original: admin_panel_backup.zip
Rejected: Extension in blacklist
```

**Benefits:**
- Prevents directory traversal attacks
- Prevents enumeration (can't guess filenames)
- Collision prevention via timestamp hash
- User ID embedded for isolation

### 7. **Organized Upload Paths**

Files are organized by date to prevent filesystem issues:

**Pattern:** `avatars/{year}/{month}/{day}/user_{userid}_{hash}.{extension}`

**Examples:**
```
avatars/2024/01/15/user_42_1704067200_a3f2.jpg
avatars/2024/01/15/user_43_1704067280_b7e1.jpg
avatars/2024/01/16/user_42_1704153600_c5d9.jpg
```

**Benefits:**
- Prevents single directory from becoming too large
- Temporal organization for maintenance
- Natural partitioning for cleanup/archival
- Reduces filesystem performance issues

### 8. **Audit Logging for Compliance**

All file upload events are logged to the AuditLog model for security investigation:

**Logged Information:**
- User ID (who uploaded)
- Filename (what was uploaded)
- File size (how large)
- MIME type (detected via magic bytes)
- IP address (from where)
- User agent (using what browser)
- Timestamp (when)
- Success/failure status
- Error message (if validation failed)

**Audit Log Examples:**

```
SUCCESS: User 42 uploaded avatar.jpg (2.3 MB) from 192.168.1.100
         MIME: image/jpeg, File stored at avatars/2024/01/15/user_42_...jpg

FAILURE: User 43 attempted upload malware.exe (5.2 MB) from 10.0.0.50
         Reason: Extension 'exe' in forbidden list
         File rejected, not stored

FAILURE: User 44 attempted upload bigfile.jpg (15 MB) from 172.16.0.20
         Reason: File size (15728640 bytes) exceeds max (5242880 bytes)
         File rejected, not stored
```

## Implementation Details

### Validator Functions

Located in `richard_musonera/file_upload_security.py`

#### `validate_avatar(file_object)`
Master validator that performs all checks:
1. File size validation
2. Magic byte validation
3. Extension validation  
4. Image dimension validation
5. Returns ValidationError if ANY check fails

#### `validate_avatar_file_size(file_object)`
Ensures file ≤ 5 MB
- Reads file size from object
- Raises ValidationError if exceeds MAX_AVATAR_SIZE

#### `validate_avatar_file_type(file_object)`
Validates using magic bytes
- Reads first 16 bytes of file
- Compares against JPEG, PNG, GIF, WebP signatures
- Raises ValidationError if no match

#### `validate_avatar_extension(file_object)`
Checks extension against blacklist
- Extracts extension from filename
- Converts to lowercase for case-insensitive check
- Raises ValidationError if in FORBIDDEN_EXTENSIONS set

#### `validate_avatar_dimensions(file_object)`
Validates image dimensions
- Opens image with Pillow library
- Checks width and height are 32-4096 pixels
- Raises ValidationError if out of range

#### `check_magic_bytes(file_object, expected_mimes)`
MIME type detection via magic bytes
- Returns detected MIME type string
- Used in audit logging to record actual file type
- Examples: 'image/jpeg', 'image/png', 'image/gif'

#### `generate_secure_filename(original_filename, user_id)`
Creates safe filename preventing traversal
- Strips path components from filename
- Extracts extension only
- Generates timestamp hash for uniqueness
- Returns: `user_{userid}_{timestamp_hash}.{ext}`

#### `avatar_upload_path(instance, filename)`
Generates secure upload directory
- Called by Django FileField with upload_to parameter
- Returns: `avatars/{year}/{month}/{day}/user_...`
- Ensures date-based organization

#### `log_file_upload(request, user_id, filename, file_size, mime_type, status, error_msg)`
Integrates with AuditLog model
- Creates audit log entry for every upload attempt
- Captures IP, user agent, timestamp
- Tracks success/failure and error reasons

### Model Integration

**File:** `richard_musonera/models.py`

```python
class UserProfile(models.Model):
    # ... other fields ...
    
    profile_picture = models.ImageField(
        upload_to=avatar_upload_path,  # Secure path generation
        validators=[validate_avatar],   # Comprehensive validation
        null=True,
        blank=True,
        help_text=f'JPG, PNG, GIF, or WebP (max {MAX_AVATAR_SIZE / (1024*1024):.0f}MB)'
    )
```

### Form Integration

**File:** `richard_musonera/forms.py`

```python
class UserProfileForm(forms.ModelForm):
    def __init__(self, *args, request=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.request = request  # Store for audit logging
        # ... field configuration ...
    
    def clean_profile_picture(self):
        profile_picture = self.cleaned_data.get('profile_picture')
        if profile_picture:
            try:
                validate_avatar(profile_picture)  # Master validator
            except forms.ValidationError as e:
                # Log failure with error details
                if self.request and self.request.user.is_authenticated:
                    log_file_upload(self.request, self.request.user.id,
                        profile_picture.name, profile_picture.size,
                        'unknown', 'failed', str(e))
                raise
        return profile_picture
    
    def save(self, commit=True, user=None, request=None):
        profile_picture = self.cleaned_data.get('profile_picture')
        if profile_picture and request and request.user.is_authenticated:
            # Detect actual MIME type via magic bytes
            mime_type = check_magic_bytes(profile_picture, ALLOWED_AVATAR_MIMES)
            # Log successful upload
            log_file_upload(request, request.user.id,
                profile_picture.name, profile_picture.size,
                mime_type, 'success', '')
        return super().save(commit=commit)
```

### View Integration

**File:** `richard_musonera/views.py`

Views pass request context through the entire upload flow:

```python
def profile_view(request):
    profile = request.user.userprofile
    
    if request.method == 'POST':
        # Pass both form data AND request for audit logging
        form = UserProfileForm(
            request.POST, 
            request.FILES,
            instance=profile, 
            user=request.user,
            request=request  # ← Enable audit logging
        )
        if form.is_valid():
            form.save(user=request.user, request=request)  # ← Log to AuditLog
            return redirect('dashboard')
    else:
        form = UserProfileForm(instance=profile, user=request.user, request=request)
    
    return render(request, 'richard_musonera/profile.html', {'form': form})
```

## Testing

Comprehensive test suite validates all security features:

**Test File:** `richard_musonera/test_file_upload_security.py`

**Test Coverage:**
- ✅ Magic byte validation (6 tests)
- ✅ File size constraints (2 tests)
- ✅ Extension blacklist (7 tests)
- ✅ Image dimension validation (3 tests)
- ✅ Secure filename generation (4 tests)
- ✅ Comprehensive avatar validation (3 tests)
- ✅ User profile upload integration (3 tests)

**Total: 28 tests, all passing**

Run tests with:
```bash
python manage.py test richard_musonera.test_file_upload_security -v 2
```

## Attack Scenarios Prevented

### Scenario 1: File Type Spoofing
```
Attacker Action: Upload "virus.exe" renamed to "avatar.jpg"
Detection: Magic byte validation reads actual content (EXE signature)
Result: Rejected due to invalid magic bytes
```

### Scenario 2: Directory Traversal
```
Attacker Action: Upload file named "../../../etc/passwd.jpg"
Defense: Filename parser extracts only basename
Result: Stored as user_42_timestamp_.jpg (no path components)
```

### Scenario 3: Resource Exhaustion via File Size
```
Attacker Action: Upload 100 MB file as "avatar.jpg"
Detection: Size validator checks file object size
Result: Rejected - exceeds MAX_AVATAR_SIZE (5 MB)
```

### Scenario 4: Image Bomb Memory Attack
```
Attacker Action: Upload crafted image claiming 4096x4096 but 1000000x1000000
Detection: Pillow Image library loads and measures actual dimensions
Result: Rejected - dimensions exceed 4096 pixel limit
```

### Scenario 5: Dangerous Script Execution
```
Attacker Action: Upload "script.py" or "malware.bat"
Detection: Extension parser checks against FORBIDDEN_EXTENSIONS blacklist
Result: Rejected - py and bat in forbidden list
```

### Scenario 6: Forensic Gap
```
Attacker Action: Upload malicious file, delete logs to cover tracks
Defense: Request context and IP logged immediately to database
Result: AuditLog entry persists even if file deleted, IP captured
```

## Best Practices for Developers

1. **Always Pass Request Context**
   - When initializing UserProfileForm, always pass `request=request`
   - Ensures audit logging captures IP and user agent
   - Enables security investigation if needed

2. **Check Audit Logs Regularly**
   - Review AuditLog table for failed uploads
   - Pattern of failures may indicate attack attempts
   - Use IP address for suspicious activity correlation

3. **Monitor File Sizes**
   - If many near-maximum-size uploads detected
   - May indicate storage exhaustion attack
   - Consider alerting on 80%+ of max size threshold

4. **Test Before Modifying Validators**
   - Changes to validators should include test cases
   - Run full test suite: `python manage.py test richard_musonera.test_file_upload_security`
   - All 28 tests must pass before deployment

5. **Keep Magic Byte Definitions Updated**
   - If adding new image formats:
     - Research official magic byte signatures
     - Add to ALLOWED_AVATAR_MIMES dictionary
     - Add test case for new format
     - Document in this guide

## Configuration Constants

Located in `richard_musonera/file_upload_security.py`:

```python
# File size limits
MAX_AVATAR_SIZE = 5 * 1024 * 1024         # 5 MB
MAX_DOCUMENT_SIZE = 10 * 1024 * 1024      # 10 MB

# Image dimension constraints
MIN_AVATAR_DIMENSION = 32                  # pixels
MAX_AVATAR_DIMENSION = 4096                # pixels

# Magic byte signatures for file type verification
ALLOWED_AVATAR_MIMES = {
    'image/jpeg': [b'\xFF\xD8\xFF'],
    'image/png': [b'\x89PNG\r\n\x1a\n'],
    'image/gif': [b'GIF87a', b'GIF89a'],
    'image/webp': [b'RIFF'],
}

# Dangerous file extensions
FORBIDDEN_EXTENSIONS = {
    'exe', 'bat', 'cmd', 'com', 'pif', 'scr', 'vbs', 'js', 'py', 
    'rb', 'sh', 'zsh', 'bash', 'pl', 'c', 'cpp', 'h', 'class', 'jar',
    'dll', 'so', 'dylib', 'sys', 'ini', 'cfg', 'conf', 'config', 'xml',
    'zip', 'rar', '7z', 'tar', 'gz', 'tar.gz', 'iso', 'dmg',
    'app', 'apk', 'msi', 'pkg', 'deb'
}
```

## Compliance and Audit Trail

All file uploads are tracked in the AuditLog model with the following event details:

- **Event Type**: `FILE_UPLOAD_SUCCESS` or `FILE_UPLOAD_FAILED`
- **User ID**: Who performed the upload
- **Filename**: Original filename provided
- **File Size**: Size in bytes
- **MIME Type**: Detected via magic bytes (success only)
- **IP Address**: Source IP of request
- **User Agent**: Browser/client information
- **Timestamp**: When the upload occurred
- **Status**: 'success' or 'failed'
- **Error Message**: Reason for rejection (if failed)

This enables:
✅ Forensic investigation of security incidents
✅ Compliance audit trails for regulatory requirements
✅ Detection of abuse patterns (repeated failures from same IP)
✅ User accountability for uploaded content
✅ Evidence preservation for security events

## References

- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [Magic Numbers in Files](https://en.wikipedia.org/wiki/List_of_file_signatures)
- [Django File Uploads](https://docs.djangoproject.com/en/4.2/topics/files/)
- [Pillow Image Documentation](https://pillow.readthedocs.io/)
