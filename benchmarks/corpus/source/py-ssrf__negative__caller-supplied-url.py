import requests


def fetch_advisory(target):
    # Deliberately NOT reported. Taking a URL is what an HTTP helper does, and
    # whether some caller passes attacker data needs a call graph this analysis
    # does not build. Reporting every such function fired 148 times across one
    # dependency tree. See "Known limitations" in the README.
    return requests.get(target)
