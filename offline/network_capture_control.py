"""Independent positive control: loopback traffic, DNS, and one TCP handshake.
No HTTP request, user files, or credentials are sent to the external endpoint.
"""
import argparse
import json
import os
import socket
import threading
import time
from pathlib import Path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    args=parser.parse_args()
    result={'pid':os.getpid(),'start':time.time(),'tests':[]}
    for family,host in ((socket.AF_INET,'127.0.0.1'),(socket.AF_INET6,'::1')):
        try:
            with socket.socket(family,socket.SOCK_STREAM) as server:
                server.bind((host,0));server.listen();server.settimeout(5)
                def echo():
                    with server.accept()[0] as peer:
                        peer.sendall(peer.recv(64))
                worker=threading.Thread(target=echo);worker.start()
                with socket.socket(family,socket.SOCK_STREAM) as client:
                    client.settimeout(5);client.connect(server.getsockname());client.sendall(b'HUOCHAT_CAPTURE_CONTROL')
                    received=client.recv(64)
                    result['tests'].append({'kind':'loopback_tcp','family':int(family),'local':client.getsockname(),'remote':client.getpeername(),'echo_ok':received==b'HUOCHAT_CAPTURE_CONTROL'})
                worker.join(timeout=5)
            with socket.socket(family,socket.SOCK_DGRAM) as server, socket.socket(family,socket.SOCK_DGRAM) as client:
                server.bind((host,0));server.settimeout(5)
                client.sendto(b'HUOCHAT_CAPTURE_CONTROL',server.getsockname())
                received,_=server.recvfrom(64)
                result['tests'].append({'kind':'loopback_udp','family':int(family),'local':client.getsockname(),'remote':server.getsockname(),'echo_ok':received==b'HUOCHAT_CAPTURE_CONTROL'})
        except OSError as error:
            result['tests'].append({'kind':'loopback','family':int(family),'error':str(error)})
    query='huochat-capture-'+str(int(time.time()))+'.invalid'
    try:
        socket.getaddrinfo(query,443)
    except OSError as error:
        result['tests'].append({'kind':'dns','query':query,'result':error.errno})
    try:
        with socket.create_connection(('1.1.1.1',443),timeout=5) as client:
            result['tests'].append({'kind':'external_tcp_handshake_only','local':client.getsockname(),'remote':client.getpeername(),'connected':True})
    except OSError as error:
        result['tests'].append({'kind':'external_tcp_handshake_only','error':str(error)})
    result['end']=time.time()
    args.output.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print('Positive control PID',result['pid'],'tests:',len(result['tests']))


if __name__=='__main__':
    main()
