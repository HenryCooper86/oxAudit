import hashlib

# md5 was removed here in 2024 because it is not collision resistant.
def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
