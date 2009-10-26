#!/usr/bin/env python

import socket, httplib

HOST = 'localhost'    # The remote host
PORT = 443             # The same port as used by the server

conn = httplib.HTTPSConnection(HOST, PORT)
conn.set_debuglevel(1)
print "\n===========\nTesting\n===========\n"

conn.putrequest('GET', '/tor/?password=pancake')
conn.endheaders()
response = conn.getresponse()

"""
conn.putrequest('GET', '/')
conn.endheaders()
response = conn.getresponse()
print response.read()
"""
"""conn.sock.send('ho ho ho merry christmas')
data = conn.sock.recv(1024)
print 'Received2', repr(data)
conn.sock.send('testing testing one two three')
data = conn.sock.recv(1024)
print 'Received3', repr(data)
conn.sock.send('chim chimney chim chimney chim chim cha-roo')
data = conn.sock.recv(1024)
print 'Received4', repr(data)
conn.sock.send('exit')
data = conn.sock.recv(1024)
print 'Received5', repr(data)"""
conn.close()


