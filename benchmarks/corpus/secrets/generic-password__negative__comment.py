import os

# The password is deliberately not stored here; see docs/credentials.md for how
# the secret is provisioned at deploy time.
def connect():
    # password comes from the environment, never from source
    return os.environ["DATABASE_PASSWORD"]
