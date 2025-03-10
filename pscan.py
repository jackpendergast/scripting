import socket
import time
import threading
from queue import Queue

socket.setdefaulttimeout(0.55)
thread_lock = threading.Lock()

target_ip = input("Please enter the target ip address: ")
port_start = int(input("Please enter the starting port: "))
port_stop = int(input("Please enter the last port: "))
nports = port_stop - port_start +1
try:
    t_ip = socket.gethostbyname(target_ip)
    print(f"Scanning ip {target_ip}")
except socket.gaierror:
    print("invalid hostname, please enter a valid ip or domain")
    exit(1)

def port_scan(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.55)
    try:
        s.connect((t_ip,port))
        with thread_lock:
            print(f"{port} is open")
        s.close()
    except:
        pass

def threader():
    while True:
        worker = q.get()
        port_scan(worker)
        q.task_done()

q = Queue()
start_time = float(time.time())

for _ in range(200):
    t = threading.Thread(target=threader)
    t.daemon = True
    t.start()

for worker in range(port_start, port_stop, +1):
    q.put(worker)

q.join()

ctime =float(time.time())
runtime = ctime - start_time
print(f"Scanned {nports} ports in {runtime:.2f} seconds")