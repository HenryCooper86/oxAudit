import subprocess


def list_directory():
    # A fixed command string with no interpolation has nothing to inject into.
    subprocess.run("ls -la", shell=True)
