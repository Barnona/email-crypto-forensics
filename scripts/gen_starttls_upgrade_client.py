import socket, ssl

HOST, PORT = "127.0.0.1", 4425

sock = socket.create_connection((HOST, PORT))
banner = sock.recv(1024)
sock.sendall(b"EHLO client.example.com\r\n")
resp = sock.recv(1024)
sock.sendall(b"STARTTLS\r\n")
resp = sock.recv(1024)

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_2

tls_sock = ctx.wrap_socket(sock, server_hostname="mail.example.com")
final = tls_sock.recv(1024)
print("client got post-TLS:", final)
tls_sock.close()
