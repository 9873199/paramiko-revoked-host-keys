"""Independent local SSH revocation checks; generated keys and socketpair only."""
import base64, hashlib, socket, threading
from pathlib import Path
import paramiko
import pytest

@pytest.fixture(scope='module')
def keys():
    return paramiko.RSAKey.generate(2048), paramiko.ECDSAKey.generate()

def line(host,key,revoked=False):
    return ('@revoked ' if revoked else '')+host+' '+key.get_name()+' '+key.get_base64()+'\n'

def exchange(tmp_path,server_key,system='',user='',hostname='unit.local',port=22,autoadd=True):
    counts={'auth':0};client=paramiko.SSHClient()
    if system:
        path=tmp_path/'system_known_hosts';path.write_text(system,encoding='utf-8');client.load_system_host_keys(str(path))
    if user:
        path=tmp_path/'user_known_hosts';path.write_text(user,encoding='utf-8');client.load_host_keys(str(path))
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy() if autoadd else paramiko.RejectPolicy())
    left,right=socket.socketpair();transport=paramiko.Transport(right);transport.add_server_key(server_key)
    class Server(paramiko.ServerInterface):
        def get_allowed_auths(self,username):return 'password'
        def check_auth_password(self,username,password):counts['auth']+=1;return paramiko.AUTH_SUCCESSFUL
    thread=threading.Thread(target=lambda:transport.start_server(server=Server()),daemon=True);thread.start()
    error=None
    try:
        client.connect(hostname,port=port,sock=left,username='test-user',password='local-test-password',allow_agent=False,look_for_keys=False,timeout=5,banner_timeout=5,auth_timeout=5)
    except Exception as exc:error=exc
    finally:
        client.close();transport.close();left.close();right.close();thread.join(timeout=5)
    return error,counts

@pytest.mark.parametrize('source',['system','user','both'])
@pytest.mark.parametrize('trusted_first',[True,False])
@pytest.mark.parametrize('autoadd',[True,False])
def test_revoked_precedes_trusted_and_policy(tmp_path,keys,source,trusted_first,autoadd):
    key=keys[0];trusted=line('unit.local',key);revoked=line('unit.local',key,True)
    if source=='both':system,user=trusted,revoked
    else:
        text=trusted+revoked if trusted_first else revoked+trusted
        system,user=(text,'') if source=='system' else ('',text)
    error,counts=exchange(tmp_path,key,system,user,autoadd=autoadd)
    assert isinstance(error,paramiko.SSHException),repr(error)
    assert counts['auth']==0,'Revocation was checked after credentials were sent'
    assert 'unit.local' in str(error),'Target missing from rejection diagnostic'
    fingerprint=base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
    assert fingerprint in str(error) or key.get_fingerprint().hex() in str(error).replace(':',''),'Public fingerprint missing'
    assert 'local-test-password' not in str(error)

@pytest.mark.parametrize('host',['unit.local,alias.local',paramiko.HostKeys.hash_host('unit.local'),'[unit.local]:2222'])
def test_revocation_host_forms(tmp_path,keys,host):
    port=2222 if host.startswith('[') else 22
    error,counts=exchange(tmp_path,keys[0],user=line(host,keys[0],True),port=port)
    assert isinstance(error,paramiko.SSHException),repr(error)
    assert counts['auth']==0

def test_unrevoked_alternative_key_uses_existing_trust(tmp_path,keys):
    rsa,ecdsa=keys
    error,counts=exchange(tmp_path,ecdsa,user=line('unit.local',rsa,True)+line('unit.local',ecdsa))
    assert error is None,repr(error)
    assert counts['auth']==1

def test_matching_revocation_different_host_is_not_global(tmp_path,keys):
    key=keys[0]
    error,counts=exchange(tmp_path,key,user=line('other.local',key,True)+line('unit.local',key))
    assert error is None,repr(error)
    assert counts['auth']==1

def test_unknown_alternative_is_not_autoaccepted_after_target_revocation(tmp_path,keys):
    rsa,ecdsa=keys
    error,counts=exchange(tmp_path,ecdsa,user=line('unit.local',rsa,True),autoadd=True)
    assert isinstance(error,paramiko.SSHException),repr(error)
    assert counts['auth']==0,'AutoAddPolicy accepted an untrusted alternative for a target with revocation configuration'

@pytest.mark.parametrize('text',[
    '@revoked unit.local\n',
    '@revoked unit.local ssh-rsa\n',
    '@revoked unit.local ssh-rsa invalid-base64!\n',
])
def test_malformed_revocation_is_not_silently_trusted_or_ignored(tmp_path,text):
    path=tmp_path/'broken-revocations';path.write_text(text,encoding='utf-8')
    with pytest.raises(Exception):paramiko.HostKeys(str(path))

def test_roundtrip_does_not_downgrade_marker(tmp_path,keys):
    path=tmp_path/'input';path.write_text(line('unit.local',keys[0],True),encoding='utf-8')
    hostkeys=paramiko.HostKeys(str(path));out=tmp_path/'saved';hostkeys.save(str(out))
    assert '@revoked' in out.read_text(encoding='utf-8')
    error,counts=exchange(tmp_path,keys[0],user=out.read_text(encoding='utf-8'))
    assert isinstance(error,paramiko.SSHException),repr(error)
    assert counts['auth']==0

def test_missing_and_corrupt_files_are_distinguishable(tmp_path):
    with pytest.raises(FileNotFoundError):paramiko.HostKeys(str(tmp_path/'missing'))
    bad=tmp_path/'malformed';bad.write_text('@revoked unit.local ssh-rsa invalid-base64!\n',encoding='utf-8')
    with pytest.raises(Exception) as caught:paramiko.HostKeys(str(bad))
    assert not isinstance(caught.value,FileNotFoundError)

def test_no_revocation_config_compatibility(tmp_path,keys):
    error,counts=exchange(tmp_path,keys[0],user=line('unit.local',keys[0]))
    assert error is None,repr(error)
    assert counts['auth']==1
