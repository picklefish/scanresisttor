#!/usr/bin/env python

import socket, ssl

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 443))
sslSocket = ssl.wrap_socket(s, cert_reqs=ssl.CERT_NONE,
                    ssl_version=ssl.PROTOCOL_SSLv3)
sslSocket.write('GET /tor/?password=pancake HTTP/1.1\r\nHost: localhost:443\r\nAccept-Encoding: identity\r\n\r\n')
data = sslSocket.recv(1024)
print 'Received1', repr(data)
sslSocket.write('testing testing one two three')
data = sslSocket.recv(1024)
print 'Received3', repr(data)
sslSocket.write('ho ho ho merry christmas')
data = sslSocket.recv(1024)
print 'Received4', repr(data)
sslSocket.write('chim chimney chim chimney chim chim cha-roo')
data = sslSocket.recv(1024)
print 'Received5', repr(data)
sslSocket.write('exit')
data = sslSocket.recv(1024)
print 'Received6', repr(data)
s.close()


"""from socket import socket
import ssl
s = socket()
c = ssl.wrap_socket(s, cert_reqs=ssl.CERT_REQUIRED,
                    ssl_version=ssl.PROTOCOL_SSLv3, ca_certs='ca.pem')
c.connect(('www.google.com', 443))
# naive and incomplete check to see if cert matches host
cert = c.getpeercert()
if not cert or ('commonName', u'www.google.com') not in cert['subject'][4]:
    raise Exception('Danger!')
c.write('GET / \n')
c.close()"""
