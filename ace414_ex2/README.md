# ACE414 Assignment 2

In this assignment, a secure server - client communication was implemented using
OpenSSL in C and TSL1.2 protocol.

---

## Secure Server - Client Program using OpenSSL

In this communication, the client sends an XML request to the
server which contains the username and password. The server verifies the XML
request, if it is valid then it sends a proper XML response to the client or gives a
message of Invalid Request.

### SSL Handshake Steps

- In the beginning of the communication, SSL/TLS client sends a “client_hello”
message to the server. This message contains all the cryptographic information
which is supported by the client, like the highest protocol version of SSL/TLS,
encryption algorithm lists, data compression method, resume session identifier,
and randomly generated data (which will be used in symmetric key generation).
- The SSL/TLS server responds with a “server_hello” message to provide all the
necessary information to establish a connection like protocol version used, data
compression algorithms and encryption method selected, assigned session id
and random data (which will be used in symmetric key generation).
- The server sends a certificate to the client and also inserts a request message
for the client certificate because the server requires the client certificate for the
mutual authentication.
- The SSL or TLS client verifies the server’s digital certificate.
- If the SSL or TLS server sent a “client certificate request”, the client sends a
random byte string encrypted with the client’s private key, together with the
client’s digital certificate, or a “no digital certificate alert”. This alert is only a
warning, but with some implementations, the handshake fails if client
authentication is mandatory.
- The SSL or TLS client sends the randomly generated data that enables both the
client and the server to compute the secret key to be used for encrypting
subsequent message data. The randomly generated data itself is encrypted with
the server’s public key.
- The SSL or TLS server verifies the client’s certificate.
- The SSL or TLS client sends the server a “finished” message, which is encrypted
with the secret key, indicating that the client part of the handshake is complete.
- The SSL or TLS server sends the client a “finished” message, which is encrypted
with the secret key, indicating that the server part of the handshake is complete.
- For the duration of the SSL or TLS session, the server and client can now
exchange messages that are symmetrically encrypted with the shared secret key.

### SSL Tool Specifications

- Before compiling the client and server program, a Certificate is needed. It can be generated using the following command:

`openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout mycert.pem -out mycert.pem`

*note: size given is 2048 bytes instead of 1024*

- Both the client and the server can be compiled with the following command:

`make`

- Firstly, the following command must be called for the server to run, in one terminal:

`sudo ./server 8082`

*note: 8082 stands for the port number in which the server listener is bound*

- Then, the following command must be called for the client to run, in another terminal:

`./client 127.0.0.1 8082`

*note: 127.0.0.1 stands for the local host IP address and 8082 stands for the port number*

---

- If the client sends a valid request to the server, then the server gives a proper response.

Client Request:  
`<Body>`  
`<User>sousi</UserName>`  
`<Password>123</Password>`  
`</Body>`  

Server Response:  
`<Body>`  
`<Name>sousi.com</Name>`  
`<year>1.5</year>`  
`<BlogType>Embedede and c c++</BlogType>`  
`<Author>John Johny</Author>`  
`</Body>`

- If the client sends an invalid request to the server, then the server gives an "Invalid Message" response.

Client Request:  
`<Body>`  
`<User>Sousi</UserName>`  
`<Password>12335</Password>`  
`</Body>`  

Server Response:  
`Invalid Response`  
