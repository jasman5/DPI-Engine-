from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd

def extract_features(pcap_file):
    packets = rdpcap(pcap_file)
    flows = {}

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        proto = ip.proto
        src = ip.src
        dst = ip.dst
        size = len(pkt)

        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        else:
            continue

        key = (src, dst, sport, dport, proto)

        if key not in flows:
            flows[key] = {
                'src_ip': src, 'dst_ip': dst,
                'src_port': sport, 'dst_port': dport,
                'protocol': proto,
                'packet_count': 0, 'total_bytes': 0,
                'min_size': size, 'max_size': size
            }

        flows[key]['packet_count'] += 1
        flows[key]['total_bytes'] += size
        flows[key]['min_size'] = min(flows[key]['min_size'], size)
        flows[key]['max_size'] = max(flows[key]['max_size'], size)

    return pd.DataFrame(flows.values())

if __name__ == "__main__":
    # df = extract_features("../test_dpi.pcap")
    df = extract_features("/mnt/c/Users/jasma/Downloads/Packet_analyzer-main/cpp/test_dpi.pcap")
    
    print(df.head())
    df.to_csv("flows.csv", index=False)