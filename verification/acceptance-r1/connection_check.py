"""An independent loopback client/server demonstration of the frozen Paramiko API."""
import argparse,base64,hashlib,os,sys
from pathlib import Path
import paramiko
from test_acceptance import exchange,line

p=argparse.ArgumentParser();p.add_argument('--scenario',choices=['revoked','trusted-alternative','untrusted-alternative','malformed-revocation'],required=True);p.add_argument('--directory',required=True);a=p.parse_args()
d=Path(a.directory);d.mkdir(parents=True,exist_ok=False)
assert Path(paramiko.__file__).resolve().is_relative_to(Path(os.environ['UF_FROZEN_ARTIFACT']).resolve())
rsa=paramiko.RSAKey.generate(2048);ecdsa=paramiko.ECDSAKey.generate()
print('Library:',paramiko.__version__)
print('Transport: local socket pair')
print('Host: unit.local')
if a.scenario=='revoked':
    print('Known hosts: trusted record plus a revoked record for the same key')
    error,counts=exchange(d,rsa,system=line('unit.local',rsa),user=line('unit.local',rsa,True))
    expected=True
elif a.scenario=='trusted-alternative':
    print('Known hosts: revoked RSA key, trusted ECDSA key')
    error,counts=exchange(d,ecdsa,user=line('unit.local',rsa,True)+line('unit.local',ecdsa))
    expected=False
elif a.scenario=='untrusted-alternative':
    print('Known hosts: revoked RSA key, unknown ECDSA key; AutoAddPolicy enabled')
    error,counts=exchange(d,ecdsa,user=line('unit.local',rsa,True))
    expected=True
else:
    print('Known hosts: trusted record followed by an incomplete @revoked record')
    error,counts=exchange(d,rsa,user=line('unit.local',rsa)+'@revoked unit.local\n')
    expected=True
print('Server authentication requests:',counts['auth'])
print('Connection result:', 'accepted' if error is None else type(error).__name__+': '+str(error))
if expected:
    ok=isinstance(error,paramiko.SSHException) and counts['auth']==0
    print('Expected behavior: refuse before authentication')
else:
    ok=error is None and counts['auth']==1
    print('Expected behavior: authenticate with the trusted alternative')
print('Observed check:', 'PASS' if ok else 'FAIL')
sys.exit(0 if ok else 1)
