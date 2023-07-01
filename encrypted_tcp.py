import struct

from scapy import *
from scapy.fields import *
from scapy.packet import Packet

#
# def unpack(pkt):
#     pkt = bytes(pkt)
#     ip_header = pkt[:20]  # IP header is 20 bytes long
#     tcp_header = pkt[20:40]  # TCP header is 20 bytes long (without options)
#     data_offset = (tcp_header[12] >> 4) * 4  # data offset is the first 4 bits of the byte at index 12
#     tcp_option = pkt[40:40 + data_offset - 20]  # TCP option is the rest of the header after index 20
#     data = pkt[40 + data_offset - 20:]  # data is the rest of the packet after the header
#     sport, dport, seq, ack, offset_reserved, flags, window, checksum, urgent = struct.unpack('!2s2sLLBBHHH', tcp_header)
#     offset = offset_reserved >> 4  # data offset is the first 4 bits of the byte
#     reserved = offset_reserved & 0xf  # reserved field is the last 4 bits of the byte
#     return data, sport, dport, seq, ack, flags
#
#
# class EncTCP:
#     def __init__(self, sport=b'\x00\x00', dport=b'\x00\x00', seq=0, ack=0, flags=0, reserved=0, tcpoption=b'\x00'):
#         self.sport = sport # source port as bytes
#         self.dport = dport # destination port as bytes
#         self.seq = seq # sequence number
#         self.ack = ack # acknowledgement number
#         self.flags = flags # flags
#         self.reserved = reserved # reserved field
#         self.tcpoption = tcpoption # tcp option field
#
#     def pack(self):
#         # pack the TCP header fields into a binary format
#         tcp_header = struct.pack('!2s2sLLBBHHH',
#             self.sport, # source port as bytes
#             self.dport, # destination port as bytes
#             self.seq, # sequence number
#             self.ack, # acknowledgement number
#             5 << 4 | self.reserved, # data offset (5 * 4 bytes) and reserved field
#             self.flags, # flags
#             65535, # window size
#             0, # checksum (0 for now)
#             0) # urgent pointer
#         return tcp_header + self.tcpoption

class EncryptedTCP(Packet):
    name = "EncryptedTCP"
    fields_desc = [

        StrFixedLenField("sport", b"\x00\x00\x00\x00\x00", 5),
        # encrypted source port with padding
        StrFixedLenField("dport", b"\x00\x00\x00\x00\x00", 5),
        # encrypted destination port with
        IntField("seq", 0),  # sequence number
        IntField("ack", 0),  # acknowledgement number
        BitField("dataofs", None, 4),  # data offset
        BitField("reserved", 0, 3),  # reserved bits
        FlagsField("flags", 0x2, 9, "FSRPAUECN"),  # flags
        ShortField("window", 8192),  # window size
        XShortField("chksum", None),  # checksum
        ShortField("urgptr", 0),  # urgent pointer
        PacketListField("options", []),  # options
        # StrFixedLenField("EncHeader", b"head", 4),
        # StrFixedLenField("EncTag", b"Tag1", 4),
        # StrFixedLenField("EncNonce", b"Nonce", 12),

        StrLenField("data", b"", length_from=lambda pkt: pkt.len - (pkt.dataofs *4))
    ]

# Define a function to slice all the fields and return them as tuples of (name, value)

# Define a function to slice all the fields and return them as tuples of (name, value)
# def slice_fields(pkt):
#     print("pkt is ",pkt)
#     result = []
#     # Slice the sport field and append it to the result list
#     sport = pkt[:5]  # sport is the first 5 bytes of the packet
#     result.append(("sport", sport))
#     # Slice the dport field and append it to the result list
#     dport = pkt[5:10]  # dport is the next 5 bytes of the packet
#     result.append(("dport", dport))
#     # Slice the seq field and append it to the result list
#     seq = pkt[10:14]  # seq is the next 4 bytes of the packet
#     result.append(("seq", seq))
#     # Slice the ack field and append it to the result list
#     ack = pkt[14:18]  # ack is the next 4 bytes of the packet
#     result.append(("ack", ack))
#     # Slice the dataofs and reserved fields and append them to the result list
#     dataofs_reserved = pkt[18]  # dataofs and reserved are in the same byte at index 18
#     result.append(("dataofs_reserved", dataofs_reserved))
#     # Slice the flags field and append it to the result list
#     flags = pkt[19]  # flags is the next byte at index 19
#     result.append(("flags", flags))
#     # Slice the window field and append it to the result list
#     window = pkt[20:22]  # window is the next 2 bytes of the packet
#     result.append(("window", window))
#     # Slice the chksum field and append it to the result list
#     chksum = pkt[22:24]  # chksum is the next 2 bytes of the packet
#     result.append(("chksum", chksum))
#     # Slice the urgptr field and append it to the result list
#     urgptr = pkt[24:26]  # urgptr is the next 2 bytes of the packet
#     result.append(("urgptr", urgptr))
#     # Slice the options field and append it to the result list
#     options = pkt[26:40]  # options is from index 26 to index 40 (14 bytes)
#     result.append(("options", options))
#     # Slice the data field and append it to the result list
#     data = pkt[40:]  # data is from index 40 to the end of the packet
#     result.append(("data", data))
#
#     return result  # return the result list
