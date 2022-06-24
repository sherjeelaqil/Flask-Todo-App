import pymysql

conn = pymysql.Connect(host="localhost", user="root", password="1234")
a = conn.cursor()
# a.execute("CREATE DATABASE personal")
a.execute("SHOW DATABASES")
for db in a:
    print(db)
