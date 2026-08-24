# Handling credentials

The scanner reports a finding when a password or client secret appears as a
literal in source. Rotate the credential first, then remove it from the file and
load it from the environment or a secrets manager instead.

A secret that has been committed should be treated as disclosed even after the
commit is amended, because the object remains reachable in the repository.
