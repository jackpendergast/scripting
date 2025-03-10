import platform
import re
import subprocess
import socket
from colorama import Fore, Style

########################################
# HELPER FUNCTIONS
########################################

def get_default_gateway():
    """
    Return (default_gateway_ip, interface_identifier).
    - On Windows, interface_identifier is the *interface IP* from 'route print'.
    - On Linux/macOS, interface_identifier is the *interface name* from 'ip route'.
    If not found, return (None, None).
    """
    system_name = platform.system().lower()
    gw_ip, gw_iface = None, None

    if 'windows' in system_name:
        try:
            route_output = subprocess.check_output(["route", "print"], encoding="utf-8", errors="ignore")
            for line in route_output.splitlines():
                cols = line.split()
                # Example line:
                #   0.0.0.0          0.0.0.0    192.168.1.1     192.168.1.123     25
                if len(cols) >= 4 and cols[0] == "0.0.0.0" and cols[1] == "0.0.0.0":
                    gw_ip = cols[2]
                    interface_ip = cols[3]
                    gw_iface = interface_ip
                    break
        except Exception:
            pass
    else:
        # On Linux/macOS, parse `ip route`:
        # e.g. "default via 192.168.1.1 dev eth0 proto static ..."
        try:
            route_output = subprocess.check_output(["ip", "route"], encoding="utf-8", errors="ignore")
            match = re.search(r"default via ([\d\.]+) dev (\S+)", route_output)
            if match:
                gw_ip = match.group(1)
                gw_iface = match.group(2)
        except Exception:
            pass

    return gw_ip, gw_iface


def get_interfaces_command():
    """
    Gather interface -> IPv4 address using only built-in commands:
      - Windows: parse 'ipconfig'
      - Linux/macOS: parse 'ip addr'
    Returns a dict: { interface_name: ipv4_address }
    """
    system_name = platform.system().lower()
    interfaces = {}

    if 'windows' in system_name:
        try:
            ipconfig_output = subprocess.check_output(["ipconfig"], encoding="utf-8", errors="ignore")
            current_iface = None
            for line in ipconfig_output.splitlines():
                line = line.strip()
                # e.g. "Ethernet adapter Ethernet:"
                if "adapter" in line.lower() and ":" in line:
                    current_iface = line.split("adapter", 1)[-1].replace(":", "").strip()
                # e.g. "IPv4 Address. . . . . . . . . . . : 192.168.1.10"
                elif ("IPv4 Address" in line or "IPv4 Address." in line) and ":" in line:
                    parts = line.split(":")
                    if len(parts) == 2:
                        ip = parts[1].strip()
                        if current_iface and ip:
                            interfaces[current_iface] = ip
        except Exception:
            pass
    else:
        # Linux/macOS: parse `ip addr`
        try:
            ip_addr_output = subprocess.check_output(["ip", "addr"], encoding="utf-8", errors="ignore")
            current_iface = None
            for line in ip_addr_output.splitlines():
                line = line.strip()
                # e.g. "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ..."
                if re.match(r"\d+:\s+.+?:", line):
                    parts = line.split(":")
                    if len(parts) >= 2:
                        current_iface = parts[1].strip()  # e.g. "eth0"
                # e.g. "inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0"
                elif line.startswith("inet "):
                    ip_match = re.search(r"inet\s+([\d\.]+)/\d+", line)
                    if ip_match and current_iface:
                        ip = ip_match.group(1)
                        interfaces[current_iface] = ip
        except Exception:
            pass

    return interfaces


def build_interface_list():
    """
    Combines interface info and default gateway to return a list of dicts:
      [
        {"name": ..., "ip": ..., "gateway": ...},
        ...
      ]
    On Windows, we match the interface IP with the gateway identifier.
    On Linux/macOS, we match the interface name with the gateway identifier.
    """
    interfaces = []
    cmd_ifaces = get_interfaces_command()
    gw_ip, gw_identifier = get_default_gateway()
    system_name = platform.system().lower()

    for if_name, ip_addr in cmd_ifaces.items():
        gw = "Unknown"
        if gw_ip and gw_identifier:
            if 'windows' in system_name:
                if ip_addr == gw_identifier:
                    gw = gw_ip
            else:
                if if_name == gw_identifier:
                    gw = gw_ip
        interfaces.append({
            "name": if_name,
            "ip": ip_addr,
            "gateway": gw
        })

    return interfaces


def choose_interface(interfaces):
    """
    Let the user pick one interface by index.
    """
    if not interfaces:
        print(Fore.RED + "No interfaces found.")
        return None

    print(Fore.CYAN + "\nAvailable Network Interfaces:")
    print(Fore.CYAN + "Index | Name                | IP Address         | Default Gateway")
    print(Fore.CYAN + "------+----------------------+--------------------+----------------")
    for i, iface in enumerate(interfaces, start=1):
        print(f"{i:<5} | {iface['name']:<20} | {iface['ip']:<18} | {iface['gateway']}")

    while True:
        choice = input(Fore.YELLOW + "\nEnter the index of the interface to use (or 'q' to quit): " + Fore.RESET)
        if choice.lower() == 'q':
            return None
        try:
            idx = int(choice)
            if 1 <= idx <= len(interfaces):
                return interfaces[idx - 1]
        except ValueError:
            pass
        print(Fore.RED + "Invalid choice. Try again.")


########################################
# SUBNET (PING SWEEP) FUNCTIONS
########################################

def ip_range_from_cidr(cidr):
    """
    Convert something like '192.168.1.0/24' into a range of integer IPs.
    We'll yield from network+1 to broadcast-1 unless prefix >= 31.
    """
    ip_str, prefix_str = cidr.split('/')
    prefix = int(prefix_str)
    parts = ip_str.split('.')
    ip_int = (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])

    host_bits = 32 - prefix
    network = (ip_int >> host_bits) << host_bits
    broadcast = network | ((1 << host_bits) - 1)

    start = network + 1
    end = broadcast - 1
    if prefix >= 31:
        # Edge case: /31 or /32
        start = network
        end = broadcast

    return range(start, end + 1)


def int_to_ip(ip_int):
    return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"


def ping_ip(ip):
    """
    Attempt to ping the IP once. Return True if alive, False otherwise.
    """
    system_name = platform.system().lower()
    count_flag = '-c' if ('linux' in system_name or 'darwin' in system_name) else '-n'
    timeout_flag = '-W' if ('linux' in system_name or 'darwin' in system_name) else '-w'

    try:
        output = subprocess.check_output(
            ["ping", count_flag, "1", timeout_flag, "1", ip],
            stderr=subprocess.STDOUT,
            encoding="utf-8"
        )
        low = output.lower()
        if "unreachable" in low or "timed out" in low:
            return False
        return True
    except:
        return False


def get_mac_from_arp(ip):
    """
    After a successful ping, parse 'arp -a' for MAC (heuristic).
    """
    system_name = platform.system().lower()
    try:
        arp_output = subprocess.check_output(["arp", "-a"], encoding="utf-8", errors="ignore")
        if 'windows' in system_name:
            # e.g. "192.168.1.15         00-1a-2b-3c-4d-5e     dynamic"
            for line in arp_output.splitlines():
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == ip:
                        return parts[1]
        else:
            # e.g. "? (192.168.1.15) at 00:1a:2b:3c:4d:5e [ether] on eth0"
            for line in arp_output.splitlines():
                if ip in line:
                    mac_match = re.search(r"(([\dA-Fa-f]{1,2}[:-]){5}[\dA-Fa-f]{1,2})", line)
                    if mac_match:
                        return mac_match.group(1)
    except Exception:
        pass
    return "N/A"


def scan_subnet(subnet):
    """
    Naive ping sweep of the given CIDR range.
    Then attempt ARP lookups for MAC addresses.
    """
    print(Fore.CYAN + f"\n[*] Scanning subnet {subnet} (ping sweep)...")
    found_hosts = []

    for ip_int in ip_range_from_cidr(subnet):
        ip_str = int_to_ip(ip_int)
        if ping_ip(ip_str):
            mac = get_mac_from_arp(ip_str)
            vendor = "Unknown"  # Not implemented here
            found_hosts.append((ip_str, mac, vendor))

    if found_hosts:
        print(Fore.GREEN + "\nFound hosts:")
        print(f"{'IP Address':<16} {'MAC Address':<18} {'Manufacturer'}")
        for ip_addr, mac, vendor in found_hosts:
            print(f"{ip_addr:<16} {mac:<18} {vendor}")
    else:
        print(Fore.RED + "No active hosts found (or insufficient privileges).")


def guess_subnet_from_ip(ip_addr):
    """
    Naive approach: if ip_addr='192.168.1.45', guess '192.168.1.0/24'.
    """
    parts = ip_addr.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return ip_addr + "/24"


########################################
# PORT SCANNING (PRIORITIZE TOP PORTS)
########################################

TOP_200_PORTS = [
    7, 20, 21, 22, 23, 25, 26, 37, 49, 53, 69, 79, 80, 81, 88, 98, 106, 109, 110, 111,
    113, 119, 123, 135, 137, 138, 139, 143, 144, 161, 162, 179, 199, 389, 427, 443, 444, 445,
    465, 500, 512, 513, 514, 515, 543, 544, 548, 554, 587, 631, 636, 873, 902, 989, 990, 993,
]


def try_connect_port(ip, port, timeout=0.2):
    """
    Helper that tries to connect to 'ip:port'.
    Returns True if open, False otherwise.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    result = s.connect_ex((ip, port))
    s.close()
    return (result == 0)


def scan_all_ports_on_host(target_ip):
    """
    1) Scan TOP_200_PORTS first, display open ones.
    2) Ask if user wants to continue scanning the rest (1..65535).
    3) If yes, scan the remaining ports, display the additional open ones.
    """
    print(Fore.CYAN + f"\n[*] Scanning ports on {target_ip} with priority for top-used ports.")

    # -- First: Scan the "top" ports --
    print(Fore.YELLOW + f"\n[*] First, scanning our top {len(TOP_200_PORTS)} ports...")
    open_top_ports = []
    for port in TOP_200_PORTS:
        if try_connect_port(target_ip, port):
            open_top_ports.append(port)

    # Display the results for the top ports
    if open_top_ports:
        print(Fore.GREEN + "\nOpen top ports:")
        for p in sorted(open_top_ports):
            print(f" - Port {p} is open")
    else:
        print(Fore.RED + "\nNo open ports found among the top ports.")

    # -- Ask if we should continue scanning the rest (1..65535) --
    choice = input(Fore.YELLOW + "\nWould you like to continue scanning ports 1..65535 (excluding the top list)? (y/n): " + Fore.RESET)
    if not choice.lower().startswith('y'):
        print(Fore.CYAN + "Skipping the rest of the ports.")
        return  # End the function here

    # -- Then: scan the rest (1..65535), skipping those in TOP_200_PORTS --
    print(Fore.YELLOW + "\n[*] Now scanning the remaining ports (1..65535), excluding the top list...")
    open_other_ports = []
    top_set = set(TOP_200_PORTS)
    for port in range(1, 65536):
        if port in top_set:
            continue  # Already scanned
        if try_connect_port(target_ip, port):
            open_other_ports.append(port)

    # Display the results for the rest of the ports
    if open_other_ports:
        print(Fore.GREEN + "\nOpen additional ports:")
        for p in sorted(open_other_ports):
            print(f" - Port {p} is open")
    else:
        print(Fore.RED + "No additional open ports found.")

    # -- Final summary --
    total_open = len(open_top_ports) + len(open_other_ports)
    print(Fore.CYAN + f"\n[*] Total open ports found on {target_ip}: {total_open}")


########################################
# MAIN
########################################

def main():
    print(Fore.MAGENTA + Style.BRIGHT + "=== Network Tools (No Third-Party Libraries) ===")
    print(Style.NORMAL + Fore.YELLOW + "Gathering interfaces from system commands...")

    interfaces = build_interface_list()
    chosen = choose_interface(interfaces)
    if not chosen:
        print(Fore.RED + "No interface chosen. Exiting.")
        return

    print(Fore.GREEN + f"\nYou chose: {chosen['name']}")
    print(Fore.GREEN + f"IP Address: {chosen['ip']}")
    print(Fore.GREEN + f"Default Gateway: {chosen['gateway']}")

    while True:
        print(Fore.MAGENTA + "\n--- Menu ---")
        print("1) Scan a subnet (ping sweep)")
        print("2) Scan TCP ports on a single IP (top ports first, then optionally more)")
        print("3) Exit")
        choice = input(Fore.YELLOW + "Select an option: " + Fore.RESET)

        if choice == '1':
            print(Fore.CYAN + "\nWould you like to scan your **own** subnet (based on chosen interface IP)?")
            print(Fore.CYAN + f"e.g. guessed from {chosen['ip']} -> {guess_subnet_from_ip(chosen['ip'])}")
            use_own = input(Fore.YELLOW + "Enter 'y' to use your IP's subnet, or 'n' to manually enter: " + Fore.RESET)
            if use_own.lower().startswith('y'):
                subnet = guess_subnet_from_ip(chosen['ip'])
            else:
                subnet = input(Fore.YELLOW + "Enter the subnet (CIDR, e.g. 192.168.1.0/24): " + Fore.RESET)
            scan_subnet(subnet)

        elif choice == '2':
            print(Fore.CYAN + "\nWould you like to scan ports on your **own** IP address or enter another?")
            print(Fore.CYAN + f"Your IP is {chosen['ip']}")
            use_own = input(Fore.YELLOW + "Enter 'y' to use your IP, or 'n' to manually enter: " + Fore.RESET)
            if use_own.lower().startswith('y'):
                target_ip = chosen['ip']
            else:
                target_ip = input(Fore.YELLOW + "Enter the IP address to scan: " + Fore.RESET)
            scan_all_ports_on_host(target_ip)

        elif choice == '3':
            print(Fore.GREEN + "Exiting...")
            break
        else:
            print(Fore.RED + "Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
