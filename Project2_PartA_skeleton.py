import __main__
import socket
import struct
import random
import json

dns_query_spec = {
    "id": random.randint(0, 65535),
    "qr": 0,      
    "opcode": 0,  
    "rd": 1,      
    "questions": [
        {
            "qname": "ilab1.cs.rutgers.edu",
            "qtype": 1,   
            "qclass": 1   
        }
    ]
}


def build_query(query_spec):
    ID = query_spec["id"]
    QR = query_spec["qr"] << 15
    OPCODE = query_spec["opcode"] << 11
    AA, TC = 0, 0
    RD = query_spec["rd"] << 8
    RA, Z, RCODE = 0, 0, 0
    flags = QR | OPCODE | AA | TC | RD | RA | Z | RCODE

    QDCOUNT = len(query_spec["questions"])
    ANCOUNT, NSCOUNT, ARCOUNT = 0, 0, 0

    header = struct.pack("!HHHHHH", ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

    question_bytes = b""
    for q in query_spec["questions"]:
        labels = q["qname"].split(".")
        for label in labels:
            question_bytes += struct.pack("B", len(label)) + label.encode()
        question_bytes += b"\x00"  
        question_bytes += struct.pack("!HH", q["qtype"], q["qclass"])

    return header + question_bytes


def parse_response(data):
    response = {}
    (ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT) = struct.unpack("!HHHHHH", data[:12])

    response["id"] = ID
    response["qr"] = (flags >> 15) & 1
    response["opcode"] = (flags >> 11) & 0xF
    response["aa"] = (flags >> 10) & 1
    response["tc"] = (flags >> 9) & 1
    response["rd"] = (flags >> 8) & 1
    response["ra"] = (flags >> 7) & 1
    response["rcode"] = flags & 0xF
    response["qdcount"] = QDCOUNT
    response["ancount"] = ANCOUNT

    offset = 12
    for _ in range(QDCOUNT):
        while data[offset] != 0:
            offset += data[offset] + 1
        offset += 1
        offset += 4  

    answers = []
    for _ in range(ANCOUNT):

        if (data[offset] & 0xC0) == 0xC0:
            offset += 2
        else:
            while data[offset] != 0:
                offset += data[offset] + 1
            offset += 1

        atype, aclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
        offset += 10
        rdata = data[offset:offset+rdlength]
        offset += rdlength

        if atype == 1 and rdlength == 4:
            ip = socket.inet_ntoa(rdata)
            answers.append({"type": "A", "ip": ip, "ttl": ttl})

        elif atype == 5:
            cname, _ = parse_name(data, offset - rdlength)
            cname_target = cname
            answers.append({"type": "CNAME", "alias": cname_target, "ttl": ttl})


    response["answers"] = answers
    return response

def parse_name(data, offset):
    labels = []
    jumped = False
    orig_offset = offset

    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                orig_offset = offset + 2  
            offset = pointer
            jumped = True
            continue

        offset += 1
        label = data[offset:offset + length].decode()
        labels.append(label)
        offset += length

    if jumped:
        return ".".join(labels), orig_offset
    else:
        return ".".join(labels), offset

def dns_query(query_spec, server=("8.8.8.8", 53)):
    query = build_query(query_spec)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(query, server)
    data, _ = sock.recvfrom(512)
    sock.close()
    result=parse_response(data)
    return result

with open("Input.json", "r") as f:
    query_json = json.load(f)

for q in query_json:

    if(q['qtype'] != 1):
        print("Invalid qtype, must be type A")
        continue
    query = dns_query_spec
    query["questions"][0]["qname"] = q['qname']
    response = dns_query(dns_query_spec)
    print(json.dumps(response, indent=2))


