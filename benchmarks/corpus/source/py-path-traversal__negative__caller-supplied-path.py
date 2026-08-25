def read_under(base, name):
    # Deliberately NOT reported: joining two parameters is what a path helper
    # does. See "Known limitations" in the README.
    return open(base + "/" + name).read()
