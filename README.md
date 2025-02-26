This repository contains two Python scripts using Scapy:

ARP Spoofing Detection - A network security tool to detect ARP poisoning attacks.
ARP Spoofing Attack - A testing script to simulate ARP spoofing attacks in a controlled environment.
🛡️ ARP Spoofing Detection
This script monitors ARP traffic and classifies packets into:
✅ Legitimate ARP messages
⚠️ Suspicious IP-MAC pair changes
🚨 Malicious ARP spoofing attempts

Features:
Detects inconsistent ARP headers
Identifies fake IP-MAC pair associations
Uses TCP ACK verification to confirm genuine hosts
Alerts on ARP reply without a prior request

⚠️ Disclaimer: This script is for ethical testing only in a lab setup or with permission. Misuse is illegal.

This script poisons the ARP cache of a victim by sending forged ARP replies, making the attacker act as a man-in-the-middle (MITM) between the target and gateway.

How It Works:
Sends fake ARP replies to the victim and gateway.
Redirects network traffic through the attacker's machine.
Allows further MITM attacks (packet sniffing, interception, etc.).
