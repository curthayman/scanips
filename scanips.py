#bycurtthecoder
import nmap
import socket

print("""
 _________          _________          _________          _________
|         |        |         |        |         |        |         |
|  I P S  |        |  C A N  |        |  T H I  |        |  N G Y  |
|  C A N  |        |  I P S  |        |  N G Y  |        |  I P S  |
|  I P S  |        |  C A N  |        |  T H I  |        |  N G Y  |
|_________|        |_________|        |_________|        |_________|
  """)

def print_colored(text, color):
    colors = {
        'green': '\033[92m',
        'red': '\033[91m'
    }
    end_color = '\033[0m'
    print(f"{colors[color]}{text}{end_color}")

scanner = nmap.PortScanner()


while True:
    target = input("Enter the IP address or domain name you want to scan (or type 'exit' to quit): ")
    if target.lower() == 'exit':
        break

    # Try to resolve the domain name to an IP address
    try:
        ip_addr = socket.gethostbyname(target)
    except socket.gaierror:
        print("Unable to resolve domain name. Please enter a valid IP address or domain name.")
        continue

    response = input("""\nEnter the type of scan you want to run
                    1. SYN ACK Scan - Requires Root
                    2. UDP Scan - Requires Root - This will take some time to run
                    3. Comprehensive Scan - Requires Root
                    4. Regular Scan
                    5. OS Detection - Requires Root
                    6. Multiple IP inputs
                    7. Ping Scan
                    8. Vulnerability Scan - This takes some time to run, around 5 minutes or longer depending on IP or domain
                    9. Exit\n""")
    print("You have selected option: ", response)
    if response == '9':
        break

    try:
        # If user's input is 1, perform a SYN/ACK scan
        if response == '1':
            print("Nmap Version: ", scanner.nmap_version())
            scanner.scan(ip_addr, '1-1024', '-v -sS')
            # Check if the IP address is up
            if scanner[ip_addr].state() == 'up':
                # Print scan information
                print("\nScan Information:")
                for info in scanner.scaninfo():
                    print(f"{info}: {scanner.scaninfo()[info]}")
                print_colored(f"\nIP Status: {scanner[ip_addr].state()}", 'green')
                print("\nProtocols:")
                for protocol in scanner[ip_addr].all_protocols():
                    print(protocol)
                print("\nOpen TCP Ports:")
                for port in scanner[ip_addr]['tcp'].keys():
                    print(f"Port {port}: {scanner[ip_addr]['tcp'][port]['state']}")
            else:
                print_colored(f"\nIP {ip_addr} is down.", 'red')

        # If user's input is 2, perform a UDP scan
        elif response == '2':
            print("Nmap Version: ", scanner.nmap_version())
            scanner.scan(ip_addr, '1-1024', '-v -sU')
            # Check if the IP address is up
            if scanner[ip_addr].state() == 'up':
                # Print scan information
                print("\nScan Information:")
                for info in scanner.scaninfo():
                    print(f"{info}: {scanner.scaninfo()[info]}")
                print_colored(f"\nIP Status: {scanner[ip_addr].state()}", 'green')
                print("\nProtocols:")
                for protocol in scanner[ip_addr].all_protocols():
                    print(protocol)
                print("\nOpen UDP Ports:")
                for port in scanner[ip_addr]['udp'].keys():
                    print(f"Port {port}: {scanner[ip_addr]['udp'][port]['state']}")
            else:
                print_colored(f"\nIP {ip_addr} is down.", 'red')

        # If user's input is 3, perform a Comprehensive scan
        elif response == '3':
            print("Nmap Version: ", scanner.nmap_version())
            scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
            # Check if the IP address is up
            if scanner[ip_addr].state() == 'up':
                # Print scan information
                print("\nScan Information:")
                for info in scanner.scaninfo():
                    print(f"{info}: {scanner.scaninfo()[info]}")
                print_colored(f"\nIP Status: {scanner[ip_addr].state()}", 'green')
                print("\nProtocols:")
                protocols = scanner[ip_addr].all_protocols()
                for protocol in protocols:
                    print(protocol)
                print("\nOpen Ports:")
                for protocol in protocols:
                    print(f"\nOpen {protocol} Ports:")
                    for port in scanner[ip_addr][protocol].keys():
                        print(f"Port {port}: {scanner[ip_addr][protocol][port]['state']}")
            else:
                print_colored(f"\nIP {ip_addr} is down.", 'red')

        # If user's input is 4, perform a Regular Scan
        elif response == '4':
            scanner.scan(ip_addr)
            # Check if the IP address is up
            if scanner[ip_addr].state() == 'up':
                # Print scan information
                print("\nScan Information:")
                for info in scanner.scaninfo():
                    print(f"{info}: {scanner.scaninfo()[info]}")
                print_colored(f"\nIP Status: {scanner[ip_addr].state()}", 'green')
                print("\nProtocols:")
                for protocol in scanner[ip_addr].all_protocols():
                    print(protocol)
                print("\nOpen TCP Ports:")
                for port in scanner[ip_addr]['tcp'].keys():
                    print(f"Port {port}: {scanner[ip_addr]['tcp'][port]['state']}")
            else:
                print_colored(f"\nIP {ip_addr} is down.", 'red')

        elif response == '5':

            scan_result = scanner.scan(ip_addr, arguments="-O")

            # Check if the IP address is in the scan results

            if ip_addr in scan_result['scan']:

                # Check if the IP address is up

                if scan_result['scan'][ip_addr]['status']['state'] == 'up':

                    # Print OS information

                    if 'osmatch' in scan_result['scan'][ip_addr]:

                        if len(scan_result['scan'][ip_addr]['osmatch']) > 0:

                            os_match = scan_result['scan'][ip_addr]['osmatch'][0]

                            print("\nOS Match:")

                            print(f"Name: {os_match['name']}")

                            print(f"Accuracy: {os_match['accuracy']}%")

                            print(f"Type: {os_match['osclass'][0]['type']}")

                            print(f"Vendor: {os_match['osclass'][0]['vendor']}")

                            print(f"OS Family: {os_match['osclass'][0]['osfamily']}")

                            print(f"OS Generation: {os_match['osclass'][0]['osgen']}")

                            print(f"CPE: {', '.join(os_match['osclass'][0]['cpe'])}")

                        else:

                            print("\nNo OS matches found.")

                    else:

                        print("\nNo OS information available.")

                else:

                    print_colored(f"\nIP {ip_addr} is down.", 'red')

            else:

                print(f"\nNo information available for IP {ip_addr}.")

        elif response == '6':
            ip_addr = input("Please enter multiple IP addresses (space separated): ")
            ip_addrs = ip_addr.split()
            # Scan each IP address
            for ip in ip_addrs:
                print(f"\nScanning IP: {ip}")
                scanner.scan(ip, '1-1024', '-v -sS')
                # Check if the IP address is up
                if scanner[ip].state() == 'up':
                    # Print scan information
                    print("\nScan Information:")
                    for info in scanner.scaninfo():
                        print(f"{info}: {scanner.scaninfo()[info]}")
                    print_colored(f"\nIP Status: {scanner[ip].state()}", 'green')
                    print("\nProtocols:")
                    for protocol in scanner[ip].all_protocols():
                        print(protocol)
                    print("\nOpen TCP Ports:")
                    for port in scanner[ip]['tcp'].keys():
                        print(f"Port {port}: {scanner[ip]['tcp'][port]['state']}")
                else:
                    print_colored(f"\nIP {ip} is down.", 'red')

        elif response == '7':
            ip_addr = input("Please enter the network address (e.g. 192.168.1.0/24): ")
            scanner.scan(hosts=ip_addr, arguments='-n -sP -PE -PA21,23,80,3389')
            # Print host list
            print("\nHost List:")
            hosts_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
            for host, status in hosts_list:
                if status == 'up':
                    print_colored(f"{host}: {status}", 'green')
                else:
                    print_colored(f"{host}: {status}", 'red')

        elif response == '8':

            scanner.scan(ip_addr, '1-1024',

'-sV --script=vuln')

            # Check if the IP address is up

            if scanner[ip_addr].state() == 'up':

                # Print scan information

                print("\nScan Information:")

                print("--------------------")

                for info in scanner.scaninfo():
                    print(f"{info}: {scanner.scaninfo()[info]}")

                print_colored(f"\nIP Status: {scanner[ip_addr].state()}", 'green')

                print("\nProtocols:")

                print("----------")

                for protocol in scanner[ip_addr].all_protocols():
                    print(protocol)

                print("\nOpen Ports:")

                print("-----------")

                for protocol in scanner[ip_addr].all_protocols():

                    print(f"\nOpen {protocol} Ports:")

                    print("------------------------")

                    for port in scanner[ip_addr][protocol].keys():
                        print(f"Port {port}: {scanner[ip_addr][protocol][port]['state']}")

                # Print vulnerability information

                print("\nVulnerability Information:")

                print("---------------------------")

                for host in scanner.all_hosts():

                    for proto in scanner[host].all_protocols():

                        print(f"\nProtocol: {proto}")

                        print("----------")

                        lport = scanner[host][proto].keys()

                        sorted(lport)

                        for port in lport:

                            print(f"Port: {port}")

                            if 'script' in scanner[host][proto][port]:

                                if 'vulners' in scanner[host][proto][port]['script']:

                                    print("Vulnerabilities:")

                                    print("---------------")

                                    vulns = scanner[host][proto][port]['script']['vulners'].split('\n')

                                    for vuln in vulns:

                                        if vuln.strip():

                                            vuln_info = vuln.split('\t')

                                            if len(vuln_info) > 1:

                                                print(f"  * {vuln_info[1]} - {vuln_info[2]}")

                                                print(f"    Severity: {vuln_info[0]}")

                                                print(f"    Reference: {vuln_info[3]}")


                                            else:

                                                print(vuln.strip())


                                else:

                                    if isinstance(scanner[host][proto][port]['script'], dict):

                                        for key, value in scanner[host][proto][port]['script'].items():
                                            print(f"{key}: {value}")

                                    else:

                                        print(scanner[host][proto][port]['script'])


                            else:

                                print(scanner[host][proto][port])


            else:

                print_colored(f"\nIP {ip_addr} is down.", 'red')

        else:
            print("Please choose a number from the options above")

    except nmap.PortScannerError as e:
        print(f"Error: {str(e)}. This operation requires root privileges. Please run the script with elevated permissions.")