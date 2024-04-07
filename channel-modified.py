import threading
from scapy.all import IP, ICMP, send, sniff

data = "Mehrshad"
payload = ''.join(hex(ord(c))[2:] for c in data)
ping_count = 10
lock = threading.Lock()

def sender():
    for _ in range(ping_count):
        packet = IP(dst="127.0.0.1") / ICMP() / bytes.fromhex(payload)
        send(packet)
        print("Sent:", packet.summary())

def receiver():
    def handle_packet(packet):
        if packet.haslayer(ICMP):
            print("Received:", packet.summary())
    
    sniff(filter="icmp", prn=handle_packet, count=ping_count)

sender_thread = threading.Thread(target=sender)
receiver_thread = threading.Thread(target=receiver)

sender_thread.start()
receiver_thread.start()

sender_thread.join()
receiver_thread.join()
