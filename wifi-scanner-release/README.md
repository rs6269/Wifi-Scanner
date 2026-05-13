#  Local WiFi Security Scanner

A simple Python desktop app I built to scan my local network. It helps identify what devices are connected, checks for open ports, and tests if the router is using weak default passwords. 

I built this to practice hands-on networking concepts and learn how basic security auditing tools work behind the scenes.

## What It Does

* **Device Discovery:** Uses ARP packets (via Scapy) to find all devices currently connected to the same WiFi network.
* **Open Port Scanner:** Checks every found device for commonly attacked open ports (like 21, 22, 80, 3389).
* **Router Password Check:** Automatically finds the default gateway (the router) and tests a short list of common default passwords against it (like admin/admin). 
* **HTML Reports:** Saves the scan results into a clean, easy-to-read HTML file so you can review the data later.

---

## Known Limitations (What it can't do yet)

Since this is a learning project, there are a few weaknesses in how it works that I plan to improve over time:

* **It only sees the current network:** Because it relies on ARP packets to find devices, it can only see things on the exact same WiFi connection. It cannot see devices on guest networks or different subnets.
* **Phones look "Suspicious":** Modern iPhones and Androids use "MAC Randomization" to hide their real hardware addresses for privacy. Because of this, the scanner can't look up their vendor name and might accidentally flag a normal phone as an "Unknown/Suspicious" device.
* **The scanner is very "loud":** The port scanning feature makes a full connection to every port it checks. This is very noisy, and any real enterprise firewall or security system would detect and block this script almost immediately.
* **Basic router checks:** The router password test only works on simple, older router login pop-ups (Basic Auth on ports 80/8080). If a modern router uses a secure webpage login or HTTPS, the scanner will just skip it.

---

## 🛠️ How to Run the Code

1. Clone this repository to your computer.
2. Install the required Python libraries:
   ```bash
   pip install -r requirements.txt