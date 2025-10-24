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

def load_root_servers(filename="root-servers"):
    """
    Load IPv4 root server addresses from a text file WITHOUT using re/os.
    Search order: './root-servers', then '/mnt/data/root-servers'.
    Lines may contain IPs with surrounding punctuation; we extract digits/dots.
    Ignores blank lines and lines starting with '#' or ';'.
    Returns a de-duped list of IPv4s preserving file order.
    """
    paths = [filename, "/mnt/data/" + filename]
    ips, seen = [], set()

    for path in paths:
        try:
            f = open(path, "r")
        except Exception:
            continue

        with f:
            for line in f:
                s = line.strip()
                if not s or s[0] in "#;":
                    continue
                for token in s.replace(",", " ").split():
                    cleaned = "".join(ch for ch in token if (ch.isdigit() or ch == "."))
                    if cleaned.count(".") != 3:
                        continue
                    parts = cleaned.split(".")
                    if len(parts) != 4:
                        continue
                    ok = True
                    for p in parts:
                        if not p.isdigit():
                            ok = False
                            break
                        n = int(p)
                        if n < 0 or n > 255:
                            ok = False
                            break
                    if ok and cleaned not in seen:
                        ips.append(cleaned)
                        seen.add(cleaned)
        break  

    return ips

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

def parse_name(data, offset):
    labels = []
    jumped = False
    original_offset = offset

    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
            pointer = struct.unpack("!H", data[offset:offset+2])[0]
            offset = pointer & 0x3FFF
            jumped = True
            continue
        labels.append(data[offset+1:offset+1+length].decode())
        offset += length + 1

    if not jumped:
        return ".".join(labels), offset
    else:
        return ".".join(labels), original_offset

def parse_rr(data, offset):
    record = {}
    hostname, offset = parse_name(data, offset)
    atype, aclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
    offset += 10
    rdata_start = offset
    rdata = data[offset:offset+rdlength]
    offset += rdlength

    type_map = {1: "A", 28: "AAAA", 2: "NS", 5: "CNAME", 6: "SOA"}
    rtype = type_map.get(atype, f"TYPE{atype}")

    record = {
        "hostname": hostname,
        "ttl": ttl,
        "atype": atype,
        "rtype": rtype,
        "ip": None,
        "nsname": None
    }

    if atype == 1 and rdlength == 4:  
        record["ip"] = socket.inet_ntoa(rdata)
    elif atype == 28 and rdlength == 16:  
        groups = []
        for i in range(0, 16, 2):
            groups.append("%x" % struct.unpack("!H", rdata[i:i+2])[0])
        record["ip"] = ":".join(groups)
    elif atype == 2:  
        nsname, _ = parse_name(data, rdata_start)
        record["nsname"] = nsname
    return record, offset

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
    response["nscount"] = NSCOUNT
    response["arcount"] = ARCOUNT

    offset = 12
    for _ in range(QDCOUNT):
        while data[offset] != 0:
            offset += data[offset] + 1
        offset += 1
        offset += 4 

    answers = []
    for _ in range(ANCOUNT):
        rr, offset = parse_rr(data, offset)
        answers.append(rr)

    authorities = []
    for _ in range(NSCOUNT):
        rr, offset = parse_rr(data, offset)
        authorities.append(rr)

    additionals = []
    for _ in range(ARCOUNT):
        rr, offset = parse_rr(data, offset)
        additionals.append(rr)

    response["answers"] = answers
    response["authorities"] = authorities
    response["additionals"] = additionals

    return response

def dns_query(query_spec, server=("1.1.1.1", 53)):
    query = build_query(query_spec)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(query, server)
    data, _ = sock.recvfrom(512)
    sock.close()
    return parse_response(data)

def iterative_resolve(query_spec):
    servers = load_root_servers("root-servers")
    print("roort servers", servers)

    if not servers:
        return {"error": "No root servers loaded from file 'root-servers'"}

    query_spec["rd"] = 0
    query_spec["id"] = 1337

    qname = query_spec["questions"][0]["qname"]
    qtype = query_spec["questions"][0]["qtype"]

    queried_servers = []

    while servers:
        server_ip = servers.pop(0)
        queried_servers.append(server_ip)

        try:
            resp = dns_query(query_spec, server=(server_ip, 53))
        except Exception:
            continue

        if resp.get("tc", 0) == 1:
            return {"error": "Truncated response (TC=1)", "queried_servers": queried_servers}

        if resp.get("rcode", 0) != 0:
            return {"error": f"DNS error RCODE={resp['rcode']}", "queried_servers": queried_servers}

        final_ips = [rr["ip"] for rr in resp.get("answers", [])
                     if rr.get("rtype") in ("A", "AAAA")
                     and rr.get("ip")
                     and rr.get("hostname") == qname]
        if final_ips:
            return {
                "qname": qname,
                "type": qtype,
                "answer_ips": final_ips,
                "queried_servers": queried_servers
            }

        ns_names = [rr["nsname"] for rr in resp.get("authorities", [])
                    if rr.get("rtype") == "NS" and rr.get("nsname")]

        glue_ips = []
        for rr in resp.get("additionals", []):
            if rr.get("rtype") in ("A", "AAAA") and rr.get("hostname") in ns_names and rr.get("ip"):
                glue_ips.append(rr["ip"])

        if not glue_ips:
            return {
                "error": "No glue found",
                "ns_candidates": ns_names,
                "queried_servers": queried_servers
            }

        servers = glue_ips + servers

    return {
        "error": "Exhausted servers without an answer",
        "queried_servers": queried_servers
    }

def _maybe_load_input_json(filename="Input.JSON"):
    """
    If Input.JSON exists (either ./Input.JSON or /mnt/data/Input.JSON), load it.
    Accepts either:
      - a list of question objects; uses the first (qname, qtype)
      - a single object with qname/qtype
    """
    for path in (filename, "/mnt/data/" + filename):
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except Exception:
            continue

        if isinstance(data, list) and data:
            first = data[0]
            if "qname" in first:
                dns_query_spec["questions"][0]["qname"] = first["qname"]
            if "qtype" in first:
                dns_query_spec["questions"][0]["qtype"] = first["qtype"]
            return True
        elif isinstance(data, dict):
            if "qname" in data:
                dns_query_spec["questions"][0]["qname"] = data["qname"]
            if "qtype" in data:
                dns_query_spec["questions"][0]["qtype"] = data["qtype"]
            return True
    return False

if __name__ == "__main__":
    _maybe_load_input_json("Input.JSON")

    response = iterative_resolve(dns_query_spec)
    print(json.dumps(response, indent=2))
