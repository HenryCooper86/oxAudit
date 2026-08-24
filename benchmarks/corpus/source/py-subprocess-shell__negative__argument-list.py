import subprocess

def run(target):
    subprocess.run(["git", "clone", target], shell=False)
