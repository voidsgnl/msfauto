import unittest
from ipaddress import ip_network

from msfauto.jobs import CheckRequest, JobError, JobManager
from msfauto.models import ScopePolicy


class JobManagerTests(unittest.TestCase):
    def test_scanner_module_completes(self) -> None:
        manager = JobManager(ScopePolicy(networks=(ip_network("192.168.56.0/24"),)))
        try:
            job_id = manager.submit(CheckRequest("lab", "192.168.56.10", 22, "tcp", "scanner/example"))
            job = manager.wait(job_id, timeout=1)
            self.assertEqual(job.status, "completed")
            self.assertTrue(manager.events(job_id))
        finally:
            manager.close()

    def test_non_scanner_module_is_unsupported(self) -> None:
        manager = JobManager(ScopePolicy(networks=(ip_network("192.168.56.0/24"),)))
        try:
            job_id = manager.submit(CheckRequest("lab", "192.168.56.10", 22, "tcp", "exploit/windows/smb/example"))
            job = manager.wait(job_id, timeout=1)
            self.assertEqual(job.status, "unsupported")
        finally:
            manager.close()

    def test_unsupported_protocol_is_skipped(self) -> None:
        manager = JobManager(ScopePolicy(networks=(ip_network("192.168.56.0/24"),)))
        try:
            job_id = manager.submit(CheckRequest("lab", "192.168.56.10", 22, "icmp", "auxiliary/scanner/ping"))
            job = manager.wait(job_id, timeout=1)
            self.assertEqual(job.status, "skipped")
        finally:
            manager.close()

    def test_failed_module_is_classified(self) -> None:
        manager = JobManager(ScopePolicy(networks=(ip_network("192.168.56.0/24"),)))
        try:
            job_id = manager.submit(CheckRequest("lab", "192.168.56.10", 22, "tcp", "auxiliary/scanner/fail"))
            job = manager.wait(job_id, timeout=1)
            self.assertEqual(job.status, "failed")
        finally:
            manager.close()

    def test_out_of_scope_target_is_rejected(self) -> None:
        manager = JobManager(ScopePolicy(networks=(ip_network("192.168.56.0/24"),)))
        try:
            with self.assertRaisesRegex(JobError, "outside"):
                manager.submit(CheckRequest("lab", "192.168.57.10", 22, "tcp", "scanner/example"))
        finally:
            manager.close()
