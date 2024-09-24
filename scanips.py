import nmap

scanner = nmap.PortScanner()

while True:
    ip_addr = input("Enter the IP address you want to scan (or type 'exit' to quit): ")
    if ip_addr.lower() == 'exit':
        break

    response = input("""\nEnter the type of scan you want to run
                    1. SYN ACK Scan
                    2. UDP Scan
                    3. Comprehensive Scan
                    4. Regular Scan
                    5. OS Detection
                    6. Multiple IP inputs
                    7. Ping Scan
                    8. Exit\n""")
    print("You have selected option: ", response)

    if response == '8':
        break

    # If user's input is 1, perform a SYN/ACK scan
    elif response == '1':
        print("Nmap Version: ", scanner.nmap_version())
        scanner.scan(ip_addr, '1-1024', '-v -sS')

        # Print scan information
        print("\nScan Information:")
        for info in scanner.scaninfo():
            print(f"{info}: {scanner.scaninfo()[info]}")

        # Print IP status
        print(f"\nIP Status: {scanner[ip_addr].state()}")

        # Print protocols
        print("\nProtocols:")
        for protocol in scanner[ip_addr].all_protocols():
            print(protocol)

        # Print open ports
        print("\nOpen Ports:")
        for port in scanner[ip_addr]['tcp'].keys():
            print(f"Port {port}")

    # If user's input is 2, perform a UDP Scan
    elif response == '2':
        print("Nmap Version: ", scanner.nmap_version())
        scanner.scan(ip_addr, '1-1024', '-v -sU')

        # Print scan information
        print("\nScan Information:")
        for info in scanner.scaninfo():
            print(f"{info}: {scanner.scaninfo()[info]}")

        # Print IP status
        print(f"\nIP Status: {scanner[ip_addr].state()}")

        # Print protocols
        print("\nProtocols:")
        for protocol in scanner[ip_addr].all_protocols():
            print(protocol)

        # Print open ports
        print("\nOpen UDP Ports:")
        for port in scanner[ip_addr]['udp'].keys():
            print(f"Port {port}")

    # If user's input is 3, perform a Comprehensive scan
    elif response == '3':
        print("Nmap Version: ", scanner.nmap_version())
        scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')

        # Print scan information
        print("\nScan Information:")
        for info in scanner.scaninfo():
            print(f"{info}: {scanner.scaninfo()[info]}")

        # Print IP status
        print(f"\nIP Status: {scanner[ip_addr].state()}")

        # Print protocols
        print("\nProtocols:")
        protocols = scanner[ip_addr].all_protocols()
        for protocol in protocols:
            print(protocol)

        # Print open ports
        print("\nOpen Ports:")
        for protocol in protocols:
            print(f"\nOpen {protocol} Ports:")
            for port in scanner[ip_addr][protocol].keys():
                print(f"Port {port}")

    # If user's input is 4, perform a Regular Scan
    elif response == '4':
        scanner.scan(ip_addr)

        # Print scan information
        print("\nScan Information:")
        for info in scanner.scaninfo():
            print(f"{info}: {scanner.scaninfo()[info]}")

        # Print IP status
        print(f"\nIP Status: {scanner[ip_addr].state()}")

        # Print protocols
        print("\nProtocols:")
        for protocol in scanner[ip_addr].all_protocols():
            print(protocol)

        # Print open ports
        print("\nOpen TCP Ports:")
        for port in scanner[ip_addr]['tcp'].keys():
            print(f"Port {port}")

    elif response == '5':
        scan_result = scanner.scan(ip_addr, arguments="-O")

        # Print OS information
        if 'osmatch' in scan_result['scan'][ip_addr]:
            if len(scan_result['scan'][ip_addr]['osmatch']) > 0:
                print("\nOS Match:")
                print(scan_result['scan'][ip_addr]['osmatch'][0])
            else:
                print("\nNo OS matches found.")
        else:
            print("\nNo OS information available.")

    elif response == '6':
        ip_addr = input("Please enter multiple IP addresses (space separated): ")
        ip_addrs = ip_addr.split()

        # Scan each IP address
        for ip in ip_addrs:
            print(f"\nScanning IP: {ip}")
            scanner.scan(ip, '1-1024', '-v -sS')

            # Print scan information
            print("\nScan Information:")
            for info in scanner.scaninfo():
                print(f"{info}: {scanner.scaninfo()[info]}")

            # Print IP status
            print(f"\nIP Status: {scanner[ip].state()}")

            # Print protocols
            print("\nProtocols:")
            for protocol in scanner[ip].all_protocols():
                print(protocol)

            # Print open ports
            print("\nOpen TCP Ports:")
            for port in scanner[ip]['tcp'].keys():
                print(f"Port {port}")

    elif response == '7':
        ip_addr = input("Please enter the network address (e.g. 192.168.1.0/24): ")
        scanner.scan(hosts=ip_addr, arguments='-n -sP -PE -PA21,23,80,3389')

        # Print host list
        print("\nHost List:")
        hosts_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
        for host, status in hosts_list:
            print(f"{host}: {status}")

    else:
        print("Please choose a number from the options above")