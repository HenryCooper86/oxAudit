import subprocess


def print_user_value(user_input):
    return subprocess.run(["printf", "%s", user_input], check=True)
