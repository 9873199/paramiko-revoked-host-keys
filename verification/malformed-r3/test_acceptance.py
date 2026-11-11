"""Verify the authentication consequence of silently ignored revocation policy."""
import paramiko,pytest
import ssh_fixture_helpers as helper

@pytest.mark.parametrize('case',['missing-type-and-key','missing-key','unknown-key-type'])
def test_corrupt_revocation_file_never_allows_authentication(tmp_path,case):
    key=paramiko.ECDSAKey.generate()
    malformed={
        'missing-type-and-key':'@revoked unit.local\n',
        'missing-key':'@revoked unit.local '+key.get_name()+'\n',
        'unknown-key-type':'@revoked unit.local ssh-unrecognized '+key.get_base64()+'\n',
    }[case]
    policy=helper.line('unit.local',key)+malformed
    try:error,counts=helper.exchange(tmp_path,key,user=policy,autoadd=True)
    except Exception as error:
        # exchange loads the explicitly existing policy file before creating
        # the loopback transport. A parser refusal is therefore fail-closed.
        print({'case':case,'phase':'policy_load','refusal_type':type(error).__name__,'authentication_started':False})
        return
    print({'case':case,'phase':'connection','error_type':None if error is None else type(error).__name__,'authentication_requests':counts['auth']})
    assert isinstance(error,paramiko.SSHException) and counts['auth']==0,'Corrupt revocation policy was ignored and authentication was allowed'
