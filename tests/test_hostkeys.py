# Copyright (C) 2006-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Some unit tests for HostKeys.
"""

from base64 import decodebytes
from binascii import hexlify
import os
import unittest

import paramiko
from paramiko.hostkeys import HostKeyEntry, HostKeys, InvalidHostKey
from paramiko.ssh_exception import RevokedHostKeyException, SSHException

from ._util import _support


test_hosts_file = """\
secure.example.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA1PD6U2/TVxET6lkpKhOk5r\
9q/kAYG6sP9f5zuUYP8i7FOFp/6ncCEbbtg/lB+A3iidyxoSWl+9jtoyyDOOVX4UIDV9G11Ml8om3\
D+jrpI9cycZHqilK0HmxDeCuxbwyMuaCygU9gS2qoRvNLWZk70OpIKSSpBo0Wl3/XUmz9uhc=
broken.example.com ssh-rsa AAAA
happy.example.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31M\
BGQ3GQ/Fc7SX6gkpXkwcZryoi4kNFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW\
5ymME3bQ4J/k1IKxCtz/bAlAqFgKoc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M=
modern.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKHEChAIxsh2hr8Q\
+Ea1AAHZyfEB2elEc2YgduVzBtp+
curvy.example.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz\
dHAyNTYAAABBBAa+pY7djSpbg5viAcZhPt56AO3U3Sd7h7dnlUp0EjfDgyYHYQxl2QZ4JGgfwR5iv9\
T9iRZjQzvJd5s+kBAZtpk=
"""

test_hosts_file_tabs = """\
secure.example.com\tssh-rsa\tAAAAB3NzaC1yc2EAAAABIwAAAIEA1PD6U2/TVxET6lkpKhOk5r\
9q/kAYG6sP9f5zuUYP8i7FOFp/6ncCEbbtg/lB+A3iidyxoSWl+9jtoyyDOOVX4UIDV9G11Ml8om3\
D+jrpI9cycZHqilK0HmxDeCuxbwyMuaCygU9gS2qoRvNLWZk70OpIKSSpBo0Wl3/XUmz9uhc=
happy.example.com\tssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31M\
BGQ3GQ/Fc7SX6gkpXkwcZryoi4kNFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW\
5ymME3bQ4J/k1IKxCtz/bAlAqFgKoc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M=
modern.example.com\tssh-ed25519\tAAAAC3NzaC1lZDI1NTE5AAAAIKHEChAIxsh2hr8Q\
+Ea1AAHZyfEB2elEc2YgduVzBtp+
curvy.example.com\tecdsa-sha2-nistp256\tAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbml\
zdHAyNTYAAABBBAa+pY7djSpbg5viAcZhPt56AO3U3Sd7h7dnlUp0EjfDgyYHYQxl2QZ4JGgfwR5iv\
9T9iRZjQzvJd5s+kBAZtpk=
"""

keyblob = b"""\
AAAAB3NzaC1yc2EAAAABIwAAAIEA8bP1ZA7DCZDB9J0s50l31MBGQ3GQ/Fc7SX6gkpXkwcZryoi4k\
NFhHu5LvHcZPdxXV1D+uTMfGS1eyd2Yz/DoNWXNAl8TI0cAsW5ymME3bQ4J/k1IKxCtz/bAlAqFgK\
oc+EolMziDYqWIATtW0rYTJvzGAzTmMj80/QpsFH+Pc2M="""


class HostKeysTest(unittest.TestCase):
    def setUp(self):
        with open("hostfile.temp", "w") as f:
            f.write(test_hosts_file)

    def tearDown(self):
        os.unlink("hostfile.temp")

    def test_load(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        assert len(hostdict) == 4
        self.assertEqual(1, len(list(hostdict.values())[0]))
        self.assertEqual(1, len(list(hostdict.values())[1]))
        fp = hexlify(
            hostdict["secure.example.com"]["ssh-rsa"].get_fingerprint()
        ).upper()
        self.assertEqual(b"E6684DB30E109B67B70FF1DC5C7F1363", fp)

    def test_add(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        hh = "|1|BMsIC6cUIP2zBuXR3t2LRcJYjzM=|hpkJMysjTk/+zzUUzxQEa2ieq6c="
        key = paramiko.RSAKey(data=decodebytes(keyblob))
        hostdict.add(hh, "ssh-rsa", key)
        assert len(hostdict) == 5
        x = hostdict["foo.example.com"]
        fp = hexlify(x["ssh-rsa"].get_fingerprint()).upper()
        self.assertEqual(b"7EC91BB336CB6D810B124B1353C32396", fp)
        self.assertTrue(hostdict.check("foo.example.com", key))

    def test_dict(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        self.assertTrue("secure.example.com" in hostdict)
        self.assertTrue("not.example.com" not in hostdict)
        self.assertTrue("secure.example.com" in hostdict)
        self.assertTrue("not.example.com" not in hostdict)
        x = hostdict.get("secure.example.com", None)
        self.assertTrue(x is not None)
        fp = hexlify(x["ssh-rsa"].get_fingerprint()).upper()
        self.assertEqual(b"E6684DB30E109B67B70FF1DC5C7F1363", fp)
        assert list(hostdict) == hostdict.keys()
        assert len(list(hostdict)) == len(hostdict.keys()) == 4

    def test_dict_set(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        key = paramiko.RSAKey(data=decodebytes(keyblob))
        key_ed25519 = paramiko.Ed25519Key.from_private_key_file(
            _support("ed25519.key")
        )
        hostdict["secure.example.com"] = {
            "ssh-rsa": key,
            "ssh-ed25519": key_ed25519,
        }
        hostdict["fake.example.com"] = {}
        hostdict["fake.example.com"]["ssh-rsa"] = key

        assert len(hostdict) == 5
        self.assertEqual(2, len(list(hostdict.values())[0]))
        self.assertEqual(1, len(list(hostdict.values())[1]))
        self.assertEqual(1, len(list(hostdict.values())[2]))
        fp = hexlify(
            hostdict["secure.example.com"]["ssh-rsa"].get_fingerprint()
        ).upper()
        self.assertEqual(b"7EC91BB336CB6D810B124B1353C32396", fp)
        fp = hexlify(
            hostdict["secure.example.com"]["ssh-ed25519"].get_fingerprint()
        ).upper()
        self.assertEqual(b"B3D522AAF9755EE8CD0EEA02B929A280", fp)

    def test_delitem(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        target = "happy.example.com"
        hostdict[target]  # will KeyError if not present
        del hostdict[target]
        try:
            hostdict[target]
        except KeyError:
            pass  # Good
        else:
            assert False, "Entry was not deleted from HostKeys on delitem!"

    def test_entry_delitem(self):
        hostdict = paramiko.HostKeys("hostfile.temp")
        target = "happy.example.com"
        entry = hostdict[target]
        key_type_list = [key_type for key_type in entry]
        for key_type in key_type_list:
            del entry[key_type]

        # will KeyError if not present
        for key_type in key_type_list:
            try:
                del entry[key_type]
            except KeyError:
                pass  # Good
            else:
                assert False, "Key was not deleted from Entry on delitem!"


class HostKeysTabsTest(HostKeysTest):
    def setUp(self):
        with open("hostfile.temp", "w") as f:
            f.write(test_hosts_file_tabs)


def _known_hosts_line(hostnames, key, revoked=False):
    marker = "@revoked " if revoked else ""
    if isinstance(hostnames, (list, tuple)):
        hostnames = ",".join(hostnames)
    return "{}{} {} {}\n".format(
        marker, hostnames, key.get_name(), key.get_base64()
    )


class HostKeyEntryRevokedTest(unittest.TestCase):
    def setUp(self):
        self.key = paramiko.ECDSAKey.generate()
        self.other = paramiko.ECDSAKey.generate(bits=384)

    def test_parse_revoked_marker(self):
        line = "@revoked alpha.example.com,beta.example.com {} {}".format(
            self.key.get_name(), self.key.get_base64()
        )
        entry = HostKeyEntry.from_line(line, 7)
        self.assertIsNotNone(entry)
        self.assertTrue(entry.revoked)
        self.assertEqual(
            ["alpha.example.com", "beta.example.com"], entry.hostnames
        )
        self.assertEqual(self.key, entry.key)

    def test_to_line_round_trips_marker(self):
        line = "@revoked alpha.example.com {} {}".format(
            self.key.get_name(), self.key.get_base64()
        )
        entry = HostKeyEntry.from_line(line, 1)
        self.assertEqual(line + "\n", entry.to_line())

    def test_repr_indicates_revocation(self):
        entry = HostKeyEntry(
            ["alpha.example.com"], self.key, revoked=True
        )
        self.assertIn("revoked", repr(entry))

    def test_unsupported_marker_is_ignored(self):
        line = "@cert-authority alpha.example.com {} {}".format(
            self.key.get_name(), self.key.get_base64()
        )
        self.assertIsNone(HostKeyEntry.from_line(line, 1))

    def test_malformed_revoked_line_raises_invalid_host_key(self):
        line = "@revoked alpha.example.com ssh-ed25519 not-base64!!!"
        with self.assertRaises(InvalidHostKey):
            HostKeyEntry.from_line(line, 3)

    def test_invalid_host_key_is_ssh_exception(self):
        # Callers catching SSHException must be able to handle corrupt files.
        line = "@revoked alpha.example.com ssh-ed25519 not-base64!!!"
        with self.assertRaises(SSHException):
            HostKeyEntry.from_line(line, 3)

    def test_short_revoked_line_returns_none(self):
        # Structurally incomplete (not enough fields) is skipped, not raised.
        self.assertIsNone(
            HostKeyEntry.from_line("@revoked alpha.example.com ssh-rsa", 1)
        )


class HostKeysRevocationTest(unittest.TestCase):
    def setUp(self):
        self.key_a = paramiko.ECDSAKey.generate()
        self.key_b = paramiko.ECDSAKey.generate(bits=384)
        self.path = "revoked_hostfile.temp"
        self.hashed = HostKeys.hash_host("hashed.example.com")
        with open(self.path, "w") as f:
            # Same key both trusted and revoked for the same host: revocation
            # must win.
            f.write(_known_hosts_line("alpha.example.com", self.key_a))
            f.write(_known_hosts_line("alpha.example.com", self.key_a, True))
            # A second key revoked for a different host.
            f.write(_known_hosts_line("beta.example.com", self.key_b, True))
            # One record naming several hostnames.
            f.write(
                _known_hosts_line(
                    ["multi1.example.com", "multi2.example.com"],
                    self.key_a,
                    True,
                )
            )
            # Hashed hostname revocation.
            f.write(_known_hosts_line(self.hashed, self.key_a, True))
            # Non-default port revocation.
            f.write(
                _known_hosts_line(
                    "[port.example.com]:2222", self.key_a, True
                )
            )
        self.hostdict = HostKeys(self.path)

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def test_revoked_key_is_reported_revoked(self):
        self.assertTrue(
            self.hostdict.is_revoked("alpha.example.com", self.key_a)
        )

    def test_revocation_takes_precedence_over_trust(self):
        # Trust record exists...
        self.assertIsNotNone(self.hostdict.lookup("alpha.example.com"))
        # ...but check() must never vouch for a revoked key.
        self.assertFalse(
            self.hostdict.check("alpha.example.com", self.key_a)
        )

    def test_revocation_is_key_specific(self):
        self.assertFalse(
            self.hostdict.is_revoked("alpha.example.com", self.key_b)
        )
        self.assertFalse(
            self.hostdict.is_revoked("beta.example.com", self.key_a)
        )

    def test_revoked_only_host_absent_from_trust_mapping(self):
        self.assertIsNone(self.hostdict.lookup("beta.example.com"))
        self.assertNotIn("beta.example.com", self.hostdict.keys())

    def test_multiple_hostnames_in_one_revoked_record(self):
        self.assertTrue(
            self.hostdict.is_revoked("multi1.example.com", self.key_a)
        )
        self.assertTrue(
            self.hostdict.is_revoked("multi2.example.com", self.key_a)
        )
        self.assertFalse(
            self.hostdict.is_revoked("multi3.example.com", self.key_a)
        )

    def test_hashed_hostname_revocation(self):
        self.assertTrue(
            self.hostdict.is_revoked("hashed.example.com", self.key_a)
        )
        self.assertFalse(
            self.hostdict.is_revoked("guessed.example.com", self.key_a)
        )

    def test_non_default_port_revocation(self):
        self.assertTrue(
            self.hostdict.is_revoked(
                "[port.example.com]:2222", self.key_a
            )
        )
        # The bare hostname is a different known-hosts token.
        self.assertFalse(
            self.hostdict.is_revoked("port.example.com", self.key_a)
        )

    def test_add_revoked_and_clear(self):
        hostdict = HostKeys()
        hostdict.add("new.example.com", self.key_a.get_name(), self.key_a)
        hostdict.add(
            "new.example.com",
            self.key_a.get_name(),
            self.key_a,
            revoked=True,
        )
        # The revoked copy lives outside the trust mapping.
        self.assertIsNotNone(hostdict.lookup("new.example.com"))
        self.assertTrue(
            hostdict.is_revoked("new.example.com", self.key_a)
        )
        self.assertFalse(
            hostdict.check("new.example.com", self.key_a)
        )
        hostdict.clear()
        self.assertFalse(
            hostdict.is_revoked("new.example.com", self.key_a)
        )
        self.assertIsNone(hostdict.lookup("new.example.com"))

    def test_save_preserves_revocation_marker(self):
        out = "revoked_hostfile_out.temp"
        try:
            self.hostdict.save(out)
            with open(out) as f:
                content = f.read()
            self.assertIn("@revoked ", content)
            # Nothing revoked may be written as a plain trust record: every
            # occurrence of the key's blob must sit on an @revoked line unless
            # it also has a genuine trust record (alpha.example.com does).
            reloaded = HostKeys(out)
            self.assertTrue(
                reloaded.is_revoked("beta.example.com", self.key_b)
            )
            self.assertTrue(
                reloaded.is_revoked("alpha.example.com", self.key_a)
            )
            self.assertFalse(
                reloaded.check("alpha.example.com", self.key_a)
            )
            # The genuinely revoked-only host is still not trusted.
            self.assertIsNone(reloaded.lookup("beta.example.com"))
        finally:
            os.unlink(out)

    def test_merged_files_combine_trust_and_revocation(self):
        # Simulate two known-hosts sources merged into one store: trust comes
        # from one file, revocation from another.
        trust_path = "revoked_trust.temp"
        revoke_path = "revoked_only.temp"
        try:
            with open(trust_path, "w") as f:
                f.write(_known_hosts_line("merged.example.com", self.key_a))
            with open(revoke_path, "w") as f:
                f.write(
                    _known_hosts_line(
                        "merged.example.com", self.key_a, True
                    )
                )
            hostdict = HostKeys()
            hostdict.load(trust_path)
            hostdict.load(revoke_path)
            self.assertTrue(
                hostdict.is_revoked("merged.example.com", self.key_a)
            )
            self.assertFalse(
                hostdict.check("merged.example.com", self.key_a)
            )
        finally:
            os.unlink(trust_path)
            os.unlink(revoke_path)

    def test_overlapping_multiname_revocation_keeps_all_hostnames(self):
        # A second revoked record partly overlaps an existing one: the already
        # covered hostname is deduplicated while the fresh hostname must still
        # end up revoked.
        first = "revoked_multi_first.temp"
        second = "revoked_multi_second.temp"
        try:
            with open(first, "w") as f:
                f.write(
                    _known_hosts_line(
                        ["one.example.com", "two.example.com"],
                        self.key_a,
                        True,
                    )
                )
            with open(second, "w") as f:
                f.write(
                    _known_hosts_line(
                        ["two.example.com", "three.example.com"],
                        self.key_a,
                        True,
                    )
                )
            hostdict = HostKeys()
            hostdict.load(first)
            hostdict.load(second)
            for host in (
                "one.example.com",
                "two.example.com",
                "three.example.com",
            ):
                self.assertTrue(
                    hostdict.is_revoked(host, self.key_a), host
                )
        finally:
            os.unlink(first)
            os.unlink(second)

    def test_malformed_revoked_line_aborts_load(self):
        path = "revoked_corrupt.temp"
        try:
            with open(path, "w") as f:
                f.write(_known_hosts_line("good.example.com", self.key_a))
                f.write(
                    "@revoked bad.example.com ssh-ed25519 not-base64!!!\n"
                )
            with self.assertRaises(InvalidHostKey):
                HostKeys(path)
        finally:
            os.unlink(path)

    def test_structurally_invalid_revoked_line_also_aborts_load(self):
        # 'nope' is valid base64 but not a valid key blob; either way a
        # corrupt @revoked record must fail closed rather than be dropped.
        path = "revoked_corrupt_struct.temp"
        try:
            with open(path, "w") as f:
                f.write("@revoked bad.example.com ssh-ed25519 nope\n")
            with self.assertRaises(SSHException):
                HostKeys(path)
        finally:
            os.unlink(path)

    def test_missing_file_distinct_from_corrupt_file(self):
        # Missing file: ordinary IO error, nothing to do with parsing.
        with self.assertRaises(IOError):
            HostKeys("definitely_not_here_{}.temp".format(os.getpid()))
        # Corrupt file: a specific parse-time exception type.
        path = "revoked_corrupt2.temp"
        try:
            with open(path, "w") as f:
                f.write(
                    "@revoked bad.example.com ssh-ed25519 not-base64!!!\n"
                )
            with self.assertRaises(InvalidHostKey):
                HostKeys(path)
        finally:
            os.unlink(path)

    def test_malformed_ordinary_line_remains_skipped(self):
        # Historical behavior: an unparseable ordinary (non-revoked) line is
        # skipped rather than aborting the whole load.
        path = "ordinary_corrupt.temp"
        try:
            with open(path, "w") as f:
                f.write("broken.example.com ssh-rsa AAAA\n")
                f.write(_known_hosts_line("good.example.com", self.key_a))
            hostdict = HostKeys(path)
            self.assertEqual(1, len(hostdict))
            self.assertIn("good.example.com", hostdict)
        finally:
            os.unlink(path)

    def test_revocation_exception_carries_target_and_public_fingerprint(self):
        exc = RevokedHostKeyException(
            "[alpha.example.com]:2222", self.key_a
        )
        message = str(exc)
        self.assertIn("[alpha.example.com]:2222", message)
        self.assertIn(self.key_a.fingerprint, message)
        self.assertEqual(self.key_a, exc.key)
        # Only public fingerprint/identity data; no private key material.
        self.assertNotIn(self.key_a.get_base64(), message)
