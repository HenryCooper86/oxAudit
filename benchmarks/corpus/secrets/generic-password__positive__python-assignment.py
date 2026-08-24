import psycopg2

# A literal credential assigned to an obviously named variable is the case this
# rule exists for.
DB_PASSWORD = "Hf83nWq2LmX9pRt4"

conn = psycopg2.connect(host="db.internal", user="svc", password=DB_PASSWORD)
