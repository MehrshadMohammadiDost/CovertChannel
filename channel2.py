from scapy.all import IP, ICMP, send

data = "Mehrshad"
payload = ''.join(hex(ord(c))[2:] for c in data)
ping_count = 10

for _ in range(ping_count):
    packet = IP(dst="127.0.0.1") / ICMP() / bytes.fromhex(payload)
    send(packet)
