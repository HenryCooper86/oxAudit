import xml.etree.ElementTree as ET


def load(path):
    # The stdlib parser resolves external entities; defusedxml exists for this.
    return ET.parse(path)
