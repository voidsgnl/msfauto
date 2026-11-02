import unittest
from ipaddress import ip_network

from msfauto.execution import CheckRequest, JobError, JobManager
from msfauto.storage.models import ActionApproval, ScopePolicy


class MemoryApprovalStore:
    def __init__(self, decision: str = "approved") -> None:
        self.decision = decision

    def get_approval(self, action_id: str):
        if action_id != "approval-1":
            return None
        return ActionApproval(
            action_id="approval-1",
            workspace="lab",
            target="192.168.56.10",
            port=22,
            protocol="tcp",
            module_name="scanner/example",
            decision=self.decision,
            approver="unit-test",
        )


class JobManagerTests(unittest.TestCase):
    def make_manager(self, decision: str = "approved") -> JobManager:
        return JobManager(
            ScopePolicy(networks=(ip_network("192.168.56.0/24"),)),
            approval_store=MemoryApprovalStore(decision),
        )

    def approved_request(self, module_name: str = "scanner/example") -> CheckRequest:
        return CheckRequest("lab", "192.168.56.10", 22, "tcp", module_name, "approval-1")

    def test_scanner_module_completes(self) -> None:
        manager = self.make_manager()
        try:
            job_id = manager.submit(self.approved_request())
            job = manager.wait(job_id, timeout=1)
            self.assertEqual(job.status, "completed")
            self.assertTrue(manager.events(job_id))
        finally:
            manager.close()

    def test_non_scanner_module_is_unsupported(self) -> None:
        manager = self.make_manager()
        try:
            job_id = manager.submit(self.approved_request("exploit/windows/smb/example"))
            job = manager.wait(job_id, timeout=1)
            self.assertEqual(job.status, "unsupported")
        finally:
            manager.close()

    def test_unsupported_protocol_is_skipped(self) -> None:
        manager = self.make_manager()
        try:
            job_id = manager.submit(self.approved_request("auxiliary/scanner/ping"))
            job = manager.wait(job_id, timeout=1)
            self.assertEqual(job.status, "skipped")
        finally:
            manager.close()

    def test_failed_module_is_classified(self) -> None:
        manager = self.make_manager()
        try:
            job_id = manager.submit(self.approved_request("auxiliary/scanner/fail"))
            job = manager.wait(job_id, timeout=1)
            self.assertEqual(job.status, "failed")
        finally:
            manager.close()


    def test_missing_approval_store_blocks_submission(self) -> None:
        manager = JobManager(ScopePolicy(networks=(ip_network("192.168.56.0/24"),)))
        try:
            with self.assertRaisesRegex(JobError, "no approval store"):
                manager.submit(self.approved_request())
        finally:
            manager.close()

    def test_rejected_approval_blocks_submission(self) -> None:
        manager = self.make_manager("rejected")
        try:
            with self.assertRaisesRegex(JobError, "does not match"):
                manager.submit(self.approved_request())
        finally:
            manager.close()

    def test_approval_for_different_module_blocks_submission(self) -> None:
        manager = self.make_manager()
        try:
            with self.assertRaisesRegex(JobError, "does not match"):
                manager.submit(self.approved_request("scanner/different"))
        finally:
            manager.close()

    def test_out_of_scope_target_is_rejected(self) -> None:
        manager = self.make_manager()
        try:
            with self.assertRaisesRegex(JobError, "outside"):
                manager.submit(CheckRequest("lab", "192.168.57.10", 22, "tcp", "scanner/example", "approval-1"))
        finally:
            manager.close()
