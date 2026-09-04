import socket, ssl, sys

HOST, PORT = "127.0.0.1", 4425

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((HOST, PORT))
srv.listen(1)
print("listening", flush=True)
conn, addr = srv.accept()

conn.sendall(b"220 mail.example.com ESMTP Postfix\r\n")
data = conn.recv(1024)  # EHLO
conn.sendall(b"250-mail.example.com\r\n250-PIPELINING\r\n250 STARTTLS\r\n")
data = conn.recv(1024)  # STARTTLS
conn.sendall(b"220 Ready to start TLS\r\n")

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/home/claude/demo/tls_capture/cert.pem", "/home/claude/demo/tls_capture/key.pem")
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_2

tls_conn = ctx.wrap_socket(conn, server_side=True)
tls_conn.sendall(b"250 mail.example.com ready after TLS\r\n")
tls_conn.close()
srv.close()
print("done", flush=True)
