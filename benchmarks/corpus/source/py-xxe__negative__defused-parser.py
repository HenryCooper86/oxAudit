import defusedxml.ElementTree as ET


def load(path):
    return ET.parse(path)
