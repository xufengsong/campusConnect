from django.conf import settings

def get_s3_audio_url(path):
    """
    Constructs a full S3 URL for a given file path using Django settings.
    If AWS_S3_CUSTOM_DOMAIN is not defined, falls back to MEDIA_URL.
    """
    if not path:
        return None
    
    # If it's already a complete URL, return it
    if str(path).startswith('http://') or str(path).startswith('https://'):
        return path

    aws_domain = getattr(settings, 'AWS_S3_CUSTOM_DOMAIN', None)
    
    # Clean up the path to avoid double slashes
    clean_path = str(path).lstrip('/')

    if aws_domain:
        # Standardizing construction: https://{domain}/{path}
        return f"https://{aws_domain}/{clean_path}"
    
    # Fallback for local development or if S3 is not configured
    media_url = getattr(settings, 'MEDIA_URL', '/media/')
    return f"{media_url}{clean_path}"
