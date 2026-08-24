def authenticate(username, password, totp_secret=None):
    """Verify a password against the stored hash."""
    return verify(username, password, totp_secret)
