"""Summarize captured ETW events and header-only PktMon PCAPNG files."""
import argparse
import collections
import datetime as dt
import ipaddress
import json
import socket
import struct
import xml.etree.ElementTree as ET
from pathlib import Path

NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}


def events(path):
    if not path.exists():
        return
    for line in path.read_text(encoding='utf-8-sig').splitlines():
        if not line.strip():
            continue
        xml = ET.fromstring(line)
        system = xml.find('e:System', NS)
        data = {d.get('Name'): d.text or '' for d in xml.findall('e:EventData/e:Data', NS)}
        provider = system.find('e:Provider', NS).get('Name')
        event_id = int(system.findtext('e:EventID', namespaces=NS))
        item = {'provider': provider, 'id': event_id,
                'utc': system.find('e:TimeCreated', NS).get('SystemTime'),
                'header_pid': int(system.find('e:Execution', NS).get('ProcessID')),
                'data': data}
        if provider.endswith('Kernel-Network') and 'PID' in data:
            item['owner_pid'] = int(data['PID'])
            for key in ('saddr', 'daddr'):
                value = data.get(key)
                if value:
                    item[key] = str(ipaddress.ip_address(struct.pack('<I', int(value)))) if value.isdecimal() else str(ipaddress.ip_address(bytes.fromhex(value)))
            for key in ('sport', 'dport'):
                if key in data:
                    item[key] = socket.ntohs(int(data[key]))
        yield item


def packets(path):
    """Yield IP tuples only; do not decode or publish other apps' payloads."""
    with path.open('rb') as stream:
        endian = '<'
        interfaces = []
        while True:
            header = stream.read(8)
            if not header:
                break
            if len(header) != 8:
                raise ValueError('Truncated PCAPNG header')
            kind, length = struct.unpack(endian+'II', header)
            if length < 12 or length > 10000000:
                raise ValueError('Invalid PCAPNG block length')
            block = stream.read(length-8)
            if len(block) != length-8 or struct.unpack_from(endian+'I', block, len(block)-4)[0] != length:
                raise ValueError('Truncated PCAPNG block')
            if kind == 0x0A0D0D0A:
                if block[:4] != b'\x4d\x3c\x2b\x1a':
                    raise ValueError('Expected native little-endian PktMon PCAPNG')
                interfaces = []
            elif kind == 1:
                linktype = struct.unpack_from('<H', block)[0]
                resolution = 1e-6
                offset = 8
                while offset+4 <= len(block)-4:
                    code, size = struct.unpack_from('<HH', block, offset)
                    if code == 0:
                        break
                    value = block[offset+4:offset+4+size]
                    if code == 9 and value:
                        resolution = 2**(-(value[0]&127)) if value[0]&128 else 10**(-value[0])
                    offset += 4 + ((size+3)//4)*4
                interfaces.append((linktype, resolution))
            elif kind == 6:
                interface, high, low, captured, original = struct.unpack_from('<IIIII', block)
                payload = block[20:20+captured]
                linktype, resolution = interfaces[interface]
                timestamp = ((high << 32) | low) * resolution
                result = {'timestamp': timestamp, 'captured': captured, 'original': original, 'linktype': linktype}
                if linktype == 1 and len(payload) >= 14:
                    protocol = struct.unpack_from('!H', payload, 12)[0]
                    offset = 14
                    while protocol in (0x8100, 0x88a8) and len(payload) >= offset+4:
                        protocol = struct.unpack_from('!H', payload, offset+2)[0]
                        offset += 4
                    ip = payload[offset:]
                    if protocol == 0x0800 and len(ip) >= 20:
                        header_length = (ip[0]&15)*4
                        result.update(ip_version=4, protocol=ip[9], saddr=socket.inet_ntop(socket.AF_INET,ip[12:16]),daddr=socket.inet_ntop(socket.AF_INET,ip[16:20]))
                        transport = ip[header_length:]
                    elif protocol == 0x86dd and len(ip) >= 40:
                        result.update(ip_version=6,protocol=ip[6],saddr=socket.inet_ntop(socket.AF_INET6,ip[8:24]),daddr=socket.inet_ntop(socket.AF_INET6,ip[24:40]))
                        transport = ip[40:]
                    else:
                        transport = b''
                    if result.get('protocol') in (6,17) and len(transport)>=4:
                        result['sport'],result['dport']=struct.unpack_from('!HH',transport)
                yield result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    args=parser.parse_args();root=args.directory
    target=list(events(root/'target-events.xml'))
    probes=list(events(root/'probe-events.xml'))
    counts=collections.Counter((x['provider'],x['id']) for x in target)
    flows=[x for x in target if x['provider'].endswith('Kernel-Network')]
    dns=[x for x in target if x['provider'].endswith('DNS-Client') and x['id']==3006]
    packet_count=0;control_packets=0;target_tuple_packets=0
    target_tuples={tuple(x.get(k) for k in ('saddr','sport','daddr','dport')) for x in flows if 'sport' in x}
    control=json.loads((root/'positive-control.json').read_text()) if (root/'positive-control.json').exists() else None
    control_ports={t['local'][1] for t in control['tests'] if t.get('kind')=='external_tcp_handshake_only' and t.get('connected')} if control else set()
    for path in sorted(root.glob('*.pcapng')):
        for packet in packets(path):
            packet_count+=1
            key=tuple(packet.get(k) for k in ('saddr','sport','daddr','dport'))
            reverse=(key[2],key[3],key[0],key[1])
            if key in target_tuples or reverse in target_tuples:
                target_tuple_packets+=1
            if control and control['start']-2 <= packet['timestamp'] <= control['end']+2 and (
                (packet.get('daddr')=='1.1.1.1' and packet.get('sport') in control_ports) or
                (packet.get('saddr')=='1.1.1.1' and packet.get('dport') in control_ports)):
                control_packets+=1
    result={'target_event_counts':{p+':'+str(i):n for (p,i),n in counts.items()},
            'target_kernel_network_events':len(flows),'target_dns_query_events':len(dns),
            'target_send_events':sum(x['id'] in (10,26,42,58) for x in flows),
            'target_connect_events':sum(x['id'] in (12,28) for x in flows),
            'captured_packets_all_processes':packet_count,'packets_matching_target_event_tuples':target_tuple_packets,
            'positive_control_packets':control_packets,'probe_events':len(probes),
            'target_events':target}
    (root/'network-summary.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='target_events'},indent=2))


if __name__=='__main__':
    main()
