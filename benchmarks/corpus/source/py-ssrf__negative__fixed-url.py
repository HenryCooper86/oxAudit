import requests


def advisories():
    return requests.get("https://api.osv.dev/v1/query")
