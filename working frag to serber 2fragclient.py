


import base64

from scapy.all import *
from scapy.layers.inet import *

import frodokem

# Define the destination IP and port
dst_ip = "192.168.68.139"
dst_port = 4449
from scapy.all import *


frodo = frodokem.FrodoKEM640()
pub, sec = frodo.keygen()
encoded = base64.b64encode(pub)
print(encoded)

print()

print("len is ", len(encoded))
def fragment_message(message, mtu=1000):
    # Calculate the number of fragments needed
    num_fragments = (len(message) + mtu - 1) // mtu
    # Create a list of fragments
    fragments = []
    # Loop through each fragment
    for i in range(num_fragments):
        # Get the start and end index of the fragment
        start = i * mtu
        end = min((i + 1) * mtu, len(message))
        # Create a packet with the fragment as payload
        packet = IP(dst=dst_ip, flags="MF") / TCP(dport=dst_port, sport=dst_port) / Raw(load=message[start:end])
        # Add the packet to the list of fragments
        fragments.append(packet)
    # Return the list of fragments
    fragments[len(fragments) - 1].flags = 0
    return fragments

# Create a TCP socket
s = conf.L3socket()

# Generate a random source port
src_port = 5555

# Create the SYN packet
syn = IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S")

# Send the SYN packet and receive the SYN-ACK packet
syn_ack = s.sr1(syn)

# Create the ACK packet
ack = IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A", ack=syn_ack.seq + 1, seq=1)

# Send the ACK packet
s.send(ack)
print("connection established")

# create a TCP data packet with the message to send to the server
server_fragments = fragment_message(encoded)
max_fr = len(server_fragments)
fr = None
last_ack = None
for i, fragment in enumerate(server_fragments):
    fr = fragment
    fragment[TCP].sport = src_port
    fragment[TCP].dport = dst_port
    fragment[TCP].seq = ack[TCP].seq + i * len(fragment[Raw])
    fragment[TCP].ack = ack[TCP].ack
    if(i < max_fr - 1):
        fragment[IP].flags = "MF"
    else:
        fragment[IP].flags = 0
    # send(fragment)
    # print(fragment.show())
    s.send(fragment)
    last_ack = s.recv()
    # print("response ",response)
    # Print a message indicating the sent fragment
    print(f"Sent fragment {i} of {len(server_fragments)}")
    # Wait for 0.1 seconds before sending the next fragment
    time.sleep(0.1)

print("waiting server response")

print("received final ack", last_ack.show())
# Initialize an empty list to store the data fragments from the client
data_frags = ""
i = 0
pkt = None
# Loop until a FIN packet is received from the client
while True:
    # Receive a packet from the client
    print("getting pkt")
    pkt = s.recv()
    print("got pkt")
    # Check if the packet is an IP fragment from the client and has a TCP layer
    # try:
    try:
        print("FLAG IS ",pkt[IP].flags)
    except: break
    if pkt[IP].src == dst_ip and (pkt[IP].flags == "MF" or pkt[IP].flags==0):
        # Print a message indicating the received fragment
        print(f"Received fragment {i}")
        # Create an ACK packet for the fragment
        ack = IP(dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="A", seq=pkt[TCP].ack, ack=pkt[TCP].seq + len(pkt[Raw]))
        # Send the ACK packet
        s.send(ack)
        # Append the fragment to the list for reassembly
        data_frags += bytes(pkt[Raw].load).decode()
        i +=1
    # except:
    if  (pkt[IP].flags == 0):
        # Print a message indicating the end of transmission
        print("End of transmission")
        # Break the loop
        break
    else:
        # s.sniff(f"tcp and dst host {src_port} and ", timeout = 5)
        continue

print("got ct")
print(data_frags)
print("len ",len(data_frags))
# Reassemble the data fragments into a single packet
# data = reassemble(data_frags)
print(data_frags)
print(len(data_frags))

ct = base64.b64decode(data_frags)
shared = frodo.decaps(ct, sec)


# Create the FIN packet
fin = IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="FA", ack=pkt[TCP].seq + 1, seq = pkt[TCP].ack)
print("sending FA")

# Send the FIN packet and receive the FIN-ACK packet
fin_ack = s.sr1(fin)
print("sent")
# Create the final ACK packet
final_ack = IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A", ack=fin_ack.seq + 1, seq = fin_ack.ack)
print("sending ACK")
# Send the final ACK packet
s.send(final_ack)
print("sent!, bye")
# Close the socket
s.close()

print("shared secret is ",shared)
