import subprocess


def deploy(target):
    # The rule matched `[^)]*` between the call and shell=True, so a nested
    # call in the arguments hid the keyword entirely and this was silently
    # missed — a false negative in a high-severity rule.
    subprocess.run(build_command(target), shell=True)
