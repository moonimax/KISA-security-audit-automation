import base64
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend import security

class SecurityFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        root=Path(self.temp.name)
        self.patches=[
            patch.object(security,"RUNTIME",root/"runtime"),
            patch.object(security,"DB",root/"runtime"/"state.db"),
            patch.object(security,"KNOWN_HOSTS",root/"runtime"/"known_hosts"),
            patch.object(security,"EVIDENCE",root/"evidence"),
        ]
        for item in self.patches:item.start()
        security.init()

    def tearDown(self):
        for item in reversed(self.patches):item.stop()
        self.temp.cleanup()

    def test_openssh_sha256_fingerprint_format(self):
        key=base64.b64encode(b"host-key-material").decode()
        expected="SHA256:"+base64.b64encode(hashlib.sha256(b"host-key-material").digest()).decode().rstrip("=")
        self.assertEqual(security.fingerprint(key),expected)

    def test_unapproved_identity_blocks_before_remote_ssh(self):
        with patch.object(security,"_ssh") as remote:
            result=security.preflight_host("192.0.2.10")
        self.assertFalse(result["ok"])
        self.assertFalse(result["checks"][0]["ok"])
        self.assertEqual(result["checks"][0]["status"], "fail")
        self.assertIn("ssh-keygen", "\n".join(result["checks"][0]["fix"]["commands"]))
        self.assertEqual(
            [check["status"] for check in result["checks"][1:4]],
            ["skip", "skip", "skip"],
        )
        remote.assert_not_called()

    def test_database_lock_rejects_overlapping_host(self):
        security.create_job("job-one","check",["host-a"])
        security.create_job("job-two","check",["host-a"])
        self.assertEqual(security.acquire_locks("job-one","check",["192.0.2.10"]),[])
        self.assertEqual(security.acquire_locks("job-two","check",["192.0.2.10"]),["192.0.2.10"])
        security.release_locks("job-one")
        self.assertEqual(security.acquire_locks("job-two","check",["192.0.2.10"]),[])


    def test_approval_requires_matching_trusted_fingerprint_and_records_audit(self):
        ip="192.0.2.20";fp="SHA256:AbCdEf0123456789"
        with security._db() as connection:
            connection.execute("""INSERT INTO identities
              (ip,port,observed_type,observed_key,observed_fp,status,scanned_at)
              VALUES(?,?,?,?,?,?,?)""",(ip,22,"ssh-ed25519","key",fp,"pending",1.0))
        with self.assertRaises(ValueError):
            security.approve(ip,"SHA256:different","admin")
        approved=security.approve(ip,fp,"admin")
        self.assertEqual(approved["status"],"trusted")
        rows=security.identity_audit(ip)
        self.assertEqual(rows[0]["result"],"approved")
        self.assertEqual(rows[0]["approver"],"admin")
        self.assertEqual(rows[1]["result"],"fingerprint_mismatch")

    def test_public_identity_hides_unapproved_observed_fingerprint(self):
        ip="192.0.2.21";fp="SHA256:NetworkObservedFingerprint"
        with security._db() as connection:
            connection.execute("""INSERT INTO identities
              (ip,port,observed_type,observed_key,observed_fp,status,scanned_at)
              VALUES(?,?,?,?,?,?,?)""",(ip,22,"ssh-ed25519","key",fp,"pending",1.0))
        public=security.public_identity(ip)
        self.assertNotIn("observed_fp",public)
        self.assertNotIn("approved_fp",public)
        self.assertEqual(public["status"],"pending")

    def test_api_session_can_be_created_verified_and_revoked(self):
        token=security.create_session("admin",ttl_seconds=60)
        self.assertEqual(security.session_user(token),"admin")
        security.revoke_session(token)
        self.assertIsNone(security.session_user(token))

    def test_lab_host_ca_initializes_once_with_restricted_private_key(self):
        self.assertFalse(security.ca_status()["ready"])
        first=security.initialize_host_ca()
        second=security.initialize_host_ca()
        self.assertTrue(first["ready"])
        self.assertEqual(first["fingerprint"],second["fingerprint"])
        self.assertEqual(security._ca_private_path().stat().st_mode & 0o777,0o600)
        self.assertIn("@cert-authority *",security.KNOWN_HOSTS.read_text())

    def test_host_ca_signs_certificate_for_hostname_and_ip(self):
        security.initialize_host_ca()
        work=Path(self.temp.name)/"host"
        result=security.subprocess.run(
            ["ssh-keygen","-q","-t","ed25519","-N","","-f",str(work)],
            capture_output=True,text=True,timeout=15,
        )
        self.assertEqual(result.returncode,0,result.stderr)
        key_type,key=Path(str(work)+".pub").read_text().split()[:2]
        certificate=security._issue_host_certificate(
            "192.0.2.22","lab-host",key_type,key
        )
        cert_type,cert_key=certificate.split()[:2]
        details=security._certificate_details(
            cert_type,cert_key,"lab-host","192.0.2.22"
        )
        self.assertEqual(details["principals"],["lab-host","192.0.2.22"])


    def test_evidence_manifest_matches_collected_files(self):
        security.create_job("evidence-job","check",["no-report-host"])
        security.append_log("evidence-job","completed\n")
        security.update_job("evidence-job",status="success",finished_at=1.0)
        directory=security.build_evidence("evidence-job")
        manifest=(directory/"manifest.sha256").read_text().splitlines()
        self.assertTrue(manifest)
        for line in manifest:
            digest,name=line.split("  ",1)
            self.assertEqual(hashlib.sha256((directory/name).read_bytes()).hexdigest(),digest)
        self.assertTrue(security.evidence_zip("evidence-job").startswith(b"PK"))
        summary=security.evidence_summary("evidence-job")
        self.assertTrue(summary["integrity_ok"])
        self.assertGreaterEqual(summary["file_count"],2)
        self.assertTrue(all(item["verified"] for item in summary["files"]))

        (directory/"execution.log").write_text("tampered\n")
        tampered=security.evidence_summary("evidence-job")
        self.assertFalse(tampered["integrity_ok"])

if __name__=="__main__":
    unittest.main()
