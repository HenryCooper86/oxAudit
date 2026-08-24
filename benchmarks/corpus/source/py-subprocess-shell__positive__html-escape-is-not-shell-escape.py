import html
import subprocess


def run(user_supplied):
    # Escaping HTML entities does not quote shell metacharacters.
    subprocess.run(html.escape(user_supplied), shell=True)
