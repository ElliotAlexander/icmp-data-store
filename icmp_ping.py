import socket
import os
import struct
import time
import datetime

# ICMP constants
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

def calculate_checksum(source_string):
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0

    while count < count_to:
        this_val = (source_string[count + 1]) * 256 + (source_string[count])
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2

    if count_to < len(source_string):
        sum = sum + (source_string[len(source_string) - 1])
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def current_milli_time():
    return round(time.time() * 1000)

def create_packet(message):
    checksum = 0
    identifier = os.getpid() & 0xFFFF

    sequence_number = 1
    data = message.encode('utf-8')
    checksum_calc_header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, checksum, identifier, sequence_number)

    checksum = calculate_checksum(checksum_calc_header + data)

    # ICMP Header: Type (8), Code (8), Checksum (16), ID (16), Sequence (16)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(checksum), identifier, sequence_number)

    return header + data

def send_ping(destination_ip, message):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError as e:
        print("Requires sudo")
        raise

    packet = create_packet(message)


    start = current_milli_time()
    sock.sendto(packet, (destination_ip, 1))
    print(f"Sent ICMP echo request with message: \"{message}\"")

    while True:

        # Drop IP header
        response, addr = sock.recvfrom(1024)
        end = current_milli_time()

        icmp_header = response[20:28]
        icmp_type, code, checksum, packet_id, sequence = struct.unpack("bbHHh", icmp_header)

        # Check if the reply is an ICMP Echo Reply
        if icmp_type == ICMP_ECHO_REPLY and packet_id == (os.getpid() & 0xFFFF):
            print(f"Received ICMP echo reply with message: \"{response[28:].decode('utf-8')}\". RTT \"{end - start}\"ms")
            break

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python icmp_ping.py <destination IP> <message>")
        sys.exit(1)

    destination_ip = sys.argv[1]
    message = sys.argv[2]

    if len(message) > 48:
        print("Message too long. Max length is 48 chars (<1473 bytes).")
        sys.exit(1)

    send_ping(destination_ip, message)

