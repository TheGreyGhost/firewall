#!/usr/bin/python
import mysql.connector

myuser = "phpmyadmin"
mypassword = input("Enter database password for " + myuser)
db = mysql.connector.connect(host="localhost",  # your host, usually localhost
                             port="8889",
                             user=myuser,  # your username
                             passwd=mypassword,  # your password
                             db="firewall")  # name of the data base

# you must create a Cursor object. It will let
#  you execute all the queries you need
cur = db.cursor()

# Use all the SQL you like
cur.execute("SELECT * FROM clients")

# print all the first cell of all the rows
for row in cur.fetchall():
    print(row[0])

db.close()
