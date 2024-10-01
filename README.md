# scanips
Nmap Scanner Tool thingy

- A simple Nmap scanner tool that allows users to perform various types of scans on IP addresses or domain names.

# Features
- SYN ACK Scan
- UDP Scan
- Comprehensive Scan
- Regular Scan
- OS Detection
- Multiple IP inputs
- Ping Scan
- Vulnerability Scan
# Requirements
Python 3.x
Nmap library (install using pip install python-nmap)
# Usage
- Clone the repository: git clone https://github.com/curthayman/scanips.git
- Install the Nmap library: pip install python-nmap
- Run the script: python scanips.py, or if using python3 it would be python3 scanips.py
# How it Works
- The script prompts the user to enter an IP or domain name to scan.
- The user is presented with a menu to choose the type of scan to perform.
- Based on the user's choice, the script performs the corresponding scan using the Nmap library.
- The scan results are printed to the console.

# Litte Demo on the Vulnerability Option
- [![Watch the video](https://haytreewebservices.com/wp-content/uploads/scanipdemoscreenshot.png)](https://haytreewebservices.com/wp-content/uploads/scanipdemo.mov)
# Example Use Cases
- Perform a SYN ACK scan on an IP address: python scanips.py and choose option 1.
- Perform a UDP scan on an IP address: python scanips.py and choose option 2.
- Perform a comprehensive scan on an IP address: python scanips.py and choose option 3.
- Perform a Vulnerability Scan on an IP address or domain name: python scanips.py and choose option 8
# Contributing
Contributions are welcome! Please submit a pull request with your changes.
# License
- This project is licensed under the MIT License. See the LICENSE file for details.
# Author
- curtthecoder
