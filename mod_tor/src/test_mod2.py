#!/usr/bin/env python

# Echo client program
import socket

HOST = 'localhost'    # The remote host
PORT = 80             # The same port as used by the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.send('GET /tor/?password=pancake HTTP/1.1\r\nHost: localhost:80\r\nAccept-Encoding: identity\r\n\r\n')
data = s.recv(1024)
print 'Received1', repr(data)
s.send('ho ho ho merry christmas')
data = s.recv(1024)
print 'Received2', repr(data)
s.send('testing testing one two three')
data = s.recv(1024)
print 'Received3', repr(data)
s.send('chim chimney chim chimney chim chim cha-roo')
data = s.recv(1024)
print 'Received4', repr(data)
s.send('exit')
data = s.recv(1024)
print 'Received5', repr(data)
s.close()


