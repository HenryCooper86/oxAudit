import sqlite3


def lookup(connection, user_id):
    # An f-string is a `string` node in the grammar, but interpolation means it
    # is not a constant. Treating it as one dropped this finding entirely — the
    # exact case the rule exists for.
    cursor = connection.cursor()
    return cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
