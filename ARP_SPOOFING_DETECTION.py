from scapy.all import sniff, send, srp1, get_if_addr, Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP
import threading
import datetime

KNOWN_IP_MAC = {}
ARP_REQUEST_LOG = {}

def monitor_arp_requests():
    """ Monitors outgoing ARP requests. """
    sniff(filter='arp', lfilter=is_outgoing_arp_request, prn=log_request, iface=conf.iface)

def monitor_arp_replies():
    """ Monitors incoming ARP replies. """
    sniff(filter='arp', lfilter=is_incoming_arp_reply, prn=analyze_arp_packet, iface=conf.iface)

def is_outgoing_arp_request(pkt):
    return pkt[ARP].op == 1 and pkt[ARP].psrc == str(get_if_addr(conf.iface))

def is_incoming_arp_reply(pkt):
    return pkt[ARP].op == 2 and pkt[ARP].psrc != str(get_if_addr(conf.iface))

def log_request(pkt):
    """ Logs ARP requests for tracking responses. """
    ARP_REQUEST_LOG[pkt[ARP].pdst] = datetime.datetime.now()

def analyze_arp_packet(pkt):
    """ Inspects ARP replies for anomalies. """
    if pkt[Ether].src != pkt[ARP].hwsrc or pkt[Ether].dst != pkt[ARP].hwdst:
        trigger_alert('ARP Header Mismatch')
        return
    check_known_mappings(pkt)

def check_known_mappings(pkt):
    """ Checks if an IP-MAC pair is known or raises an alert. """
    ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
    
    if ip in KNOWN_IP_MAC:
        if KNOWN_IP_MAC[ip] != mac:
            trigger_alert('IP-MAC Pair Mismatch')
    else:
        validate_new_mapping(pkt)

def validate_new_mapping(pkt):
    """ Verifies if a new ARP mapping is legitimate. """
    ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
    timestamp = datetime.datetime.now()
    
    if ip in ARP_REQUEST_LOG and (timestamp - ARP_REQUEST_LOG[ip]).total_seconds() <= 5:
        verify_tcp_connection(ip, mac)
    else:
        send_arp_probe(ip)

def verify_tcp_connection(ip, mac):
    """ Confirms authenticity by sending a TCP SYN packet. """
    syn_packet = Ether(dst=mac) / IP(dst=ip) / TCP(sport=40508, dport=40508, flags="S", seq=10000)
    response = srp1(syn_packet, verbose=False, timeout=2)
    
    if response:
        KNOWN_IP_MAC[ip] = mac
    else:
        trigger_alert('Unverified IP-MAC Mapping')

def send_arp_probe(ip):
    """ Sends an ARP request to confirm legitimate ownership. """
    send(ARP(op=1, pdst=ip), verbose=False)

def trigger_alert(alert_msg):
    """ Raises an alert for detected anomalies. """
    print(f'ALERT: {alert_msg}')

if __name__ == "__main__":
    threading.Thread(target=monitor_arp_requests, daemon=True).start()
    threading.Thread(target=monitor_arp_replies, daemon=True).start()
