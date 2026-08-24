import subprocess


def run_user_command(user_input):
    return subprocess.run(user_input, shell=True, check=True)
