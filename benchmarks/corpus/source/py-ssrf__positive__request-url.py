from flask import request
import requests


def proxy():
    # The destination comes from the inbound request, so a caller can aim the
    # server at anything it can reach.
    return requests.get(request.args.get("target"))
