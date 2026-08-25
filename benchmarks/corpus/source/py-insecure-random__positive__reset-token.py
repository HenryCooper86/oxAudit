import random
import string


def reset_token():
    return "".join(random.choice(string.ascii_letters) for _ in range(32))
