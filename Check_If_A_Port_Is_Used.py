def Check_If_A_Port_Is_Used():
        #check if a port is in use
        import socket

        port = int(input("Which port would you like to scan?: "))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(("10.16.128.164",port))
        # print(f"{port} is {'in use' if result == 0 else 'available'}")
        if(result == 0):
            print(f"port {port} is in use")
        else:
            print(f"Port {port} is available")

if __name__ == "__main__":
    Check_If_A_Port_Is_Used()