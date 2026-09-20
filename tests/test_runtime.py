import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from backend import inventory_sync, jobs, main, security
from backend.runtime import RUNTIMES, domain_for_code

class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.security_temp = tempfile.TemporaryDirectory()
        root = Path(self.security_temp.name)
        self.security_patches = [
            patch.object(security, "RUNTIME", root / "runtime"),
            patch.object(security, "DB", root / "runtime" / "state.db"),
            patch.object(security, "KNOWN_HOSTS", root / "runtime" / "known_hosts"),
            patch.object(security, "EVIDENCE", root / "evidence"),
        ]
        for item in self.security_patches:
            item.start()
        security.init()

    def tearDown(self):
        for item in reversed(self.security_patches):
            item.stop()
        self.security_temp.cleanup()

    def test_backend_startup_does_not_rewrite_inventory(self) -> None:
        with patch.object(main.db, "init_db") as init_db, patch.object(
            main.inventory_sync, "sync_inventory"
        ) as sync_inventory:
            main.on_startup()

        init_db.assert_called_once_with()
        sync_inventory.assert_not_called()

    def test_all_domains_share_playbook_entrypoint_names(self) -> None:
        for domain, runtime in RUNTIMES.items():
            with self.subTest(domain=domain):
                self.assertEqual(runtime.deploy_playbook, "playbooks/deploy.yml")
                self.assertEqual(runtime.check_playbook, "playbooks/check.yml")
                self.assertEqual(runtime.audit_playbook, "playbooks/audit.yml")
                self.assertEqual(
                    runtime.remediate_playbook,
                    "playbooks/remediate_approved.yml",
                )

    def test_all_runtime_playbooks_exist(self) -> None:
        for domain, runtime in RUNTIMES.items():
            with self.subTest(domain=domain):
                for playbook in (
                    runtime.deploy_playbook,
                    runtime.check_playbook,
                    runtime.audit_playbook,
                    runtime.remediate_playbook,
                ):
                    if playbook:
                        self.assertTrue((runtime.root / playbook).is_file(), playbook)


    def test_code_prefix_selects_domain(self) -> None:
        self.assertEqual(domain_for_code("U-01"), "UNIX")
        self.assertEqual(domain_for_code("WEB-01"), "WEB")
        self.assertEqual(domain_for_code("D-01"), "DBMS")
        with self.assertRaises(ValueError):
            domain_for_code("W-01")

    def test_all_domains_only_include_supported_hosts(self) -> None:
        hosts = [
            ("unix-db", "192.0.2.10", ["UNIX", "DBMS"]),
            ("web", "192.0.2.11", ["WEB"]),
        ]
        self.assertEqual(
            jobs._domain_targets(hosts, ["ALL"]),
            {
                "UNIX": [("unix-db", "192.0.2.10")],
                "WEB": [("web", "192.0.2.11")],
                "DBMS": [("unix-db", "192.0.2.10")],
            },
        )

    def test_inventory_sync_splits_hosts_by_domain(self) -> None:
        hosts = [
            {"hostname": "unix-db", "ip": "192.0.2.10", "domains": ["UNIX", "DBMS"]},
            {"hostname": "web", "ip": "192.0.2.11", "domains": ["WEB"]},
        ]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            runtimes = {
                name: replace(runtime, inventory=base / name / "hosts.ini")
                for name, runtime in RUNTIMES.items()
            }
            runtimes["DBMS"].inventory.parent.mkdir(parents=True)
            runtimes["DBMS"].inventory.write_text(
                "[mysql_servers]\nold-name ansible_host=192.0.2.10 ansible_user=mysql-admin\n"
            )
            unified_inventory = base / "inventory" / "hosts.ini"
            with patch.object(inventory_sync, "RUNTIMES", runtimes), patch.object(
                inventory_sync, "UNIFIED_INVENTORY", unified_inventory
            ), patch.object(inventory_sync.db, "list_hosts", return_value=hosts):
                inventory_sync.sync_inventory()

            self.assertIn("unix-db ansible_host=192.0.2.10", runtimes["UNIX"].inventory.read_text())
            self.assertNotIn("web ansible_host", runtimes["UNIX"].inventory.read_text())
            self.assertIn("web ansible_host=192.0.2.11", runtimes["WEB"].inventory.read_text())
            self.assertIn("[mysql_servers]", runtimes["DBMS"].inventory.read_text())
            self.assertIn("ansible_user=mysql-admin", runtimes["DBMS"].inventory.read_text())
            unified = unified_inventory.read_text()
            self.assertIn("[control_nodes]", unified)
            self.assertIn("[unix_targets]", unified)
            self.assertIn("[web_targets]", unified)
            self.assertIn("[dbms_targets]", unified)

    def test_playbook_runs_from_domain_root(self) -> None:
        runtime = RUNTIMES["WEB"]
        job_id = jobs._new_job("test", ["web"])
        completed = SimpleNamespace(returncode=0, stdout="ok", stderr="")
        with patch.object(jobs.subprocess, "run", return_value=completed) as run:
            self.assertTrue(
                jobs._run_playbook(job_id, runtime, runtime.check_playbook, {}, "web")
            )
        command = run.call_args.args[0]
        self.assertEqual(run.call_args.kwargs["cwd"], runtime.root)
        self.assertEqual(command[0:3], ["ansible-playbook", "-i", str(runtime.inventory)])
        self.assertIn(runtime.check_playbook, command)

    def test_web_check_deploys_before_check_and_audit(self) -> None:
        job_id = jobs._new_job("test", ["web"])
        with patch.object(jobs, "_run_playbook", return_value=True) as run, patch.object(
            jobs, "_ingest_host_report"
        ):
            jobs._run_check_job(
                job_id,
                [("web", "192.0.2.11", ["WEB"])],
                ["WEB"],
            )

        runtime = RUNTIMES["WEB"]
        self.assertEqual(
            [call.args[2] for call in run.call_args_list],
            [runtime.deploy_playbook, runtime.check_playbook, runtime.audit_playbook],
        )


    def test_check_only_skips_audit_playbook(self) -> None:
        job_id = jobs._new_job("test", ["web"])
        with patch.object(jobs, "_run_playbook", return_value=True) as run, patch.object(
            jobs, "_ingest_host_report"
        ):
            jobs._run_check_only_job(
                job_id,
                [("web", "192.0.2.11", ["WEB"])],
                ["WEB"],
            )

        runtime = RUNTIMES["WEB"]
        self.assertEqual(
            [call.args[2] for call in run.call_args_list],
            [runtime.deploy_playbook, runtime.check_playbook],
        )
        self.assertNotIn(runtime.audit_playbook, [call.args[2] for call in run.call_args_list])

    def test_automatic_updates_compare_initial_and_remediated_status(self) -> None:
        before = [
            {"code":"U-01","title":"root 원격 접속 제한","status":"취약","severity":"상","action_tag":"자동조치"},
            {"code":"U-02","title":"패스워드 복잡성","status":"취약","severity":"중","action_tag":"승인요청"},
        ]
        after = [
            {"code":"U-01","title":"root 원격 접속 제한","status":"양호","severity":"상","action_tag":"자동조치"},
            {"code":"U-02","title":"패스워드 복잡성","status":"취약","severity":"중","action_tag":"승인요청"},
        ]

        updates = jobs._automatic_updates("192.0.2.10", before, after)

        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0]["source"], "자동조치")
        self.assertEqual(updates[0]["outcome"], "fixed")
        self.assertEqual((updates[0]["before"], updates[0]["after"]), ("취약", "양호"))

    def test_security_score_preserves_initial_and_final_difference(self) -> None:
        initial = [
            {"status":"취약","severity":"상"},
            {"status":"양호","severity":"중"},
        ]
        final = [
            {"status":"양호","severity":"상"},
            {"status":"양호","severity":"중"},
        ]

        self.assertEqual(jobs._score(initial), 44.44)
        self.assertEqual(jobs._score(final), 100.0)

    def test_dbms_check_uses_standard_pipeline(self) -> None:
        job_id = jobs._new_job("test", ["db"])
        with patch.object(jobs, "_run_playbook", return_value=True) as run, patch.object(
            jobs, "_ingest_host_report"
        ):
            jobs._run_check_job(
                job_id,
                [("db", "192.0.2.12", ["DBMS"])],
                ["DBMS"],
            )

        runtime = RUNTIMES["DBMS"]
        self.assertEqual(
            [call.args[2] for call in run.call_args_list],
            [runtime.deploy_playbook, runtime.check_playbook, runtime.audit_playbook],
        )
        self.assertEqual(run.call_args_list[-1].args[3], {})

if __name__ == "__main__":
    unittest.main()
