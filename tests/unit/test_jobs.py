import sqlite3
import unittest
from ipaddress import ip_network

from msfauto.execution import CheckRequest, JobError, JobManager
from msfauto.storage.models import ActionApproval, ScopePolicy


class MemoryApprovalStore:
    def __init__(
        self,
        decision: str = "approved",
        module_name: str = "scanner/example",
        target: str = "192.168.56.10",
        protocol: str = "tcp",
        revoke_after_submit: bool = False,
    ) -> None:
        self.decision = decision
        self.module_name = module_name
        self.target = target
        self.protocol = protocol
        self.revoke_after_submit = revoke_after_submit
        self.calls = 0

    def get_approval(self, action_id: str) -> ActionApproval | None:
        if action_id != "approval-1":
            return None
        self.calls += 1
        decision = "rejected" if self.revoke_after_submit and self.calls > 1 else self.decision
        return ActionApproval(
            action_id="approval-1",
            workspace="lab",
            target=self.target,
            port=22,
            protocol=self.protocol,
            module_name=self.module_name,
            decision=decision,
            approver="unit-test",
        )


class JobManagerTests(unittest.TestCase):
    def make_manager(
        self,
        decision: str = "approved",
        module_name: str = "scanner/example",
        target: str = "192.168.56.10",
        protocol: str = "tcp",
    ) -> JobManager:
        return JobManager(
            ScopePolicy(networks=(ip_network("192.168.56.0/24"),)),
            approval_store=MemoryApprovalStore(decision, module_name, target, protocol),
        )

    def approved_request(
        self,
        module_name: str = "scanner/example",
        target: str = "192.168.56.10",
        protocol: str = "tcp",
        risk: str = "non-invasive",
    ) -> CheckRequest:
        return CheckRequest("lab", target, 22, protocol, module_name, "approval-1", risk)

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
        manager = self.make_manager(module_name="exploit/windows/smb/example")
        try:
            job_id = manager.submit(self.approved_request("exploit/windows/smb/example"))
            job = manager.wait(job_id, timeout=1)
            self.assertEqual(job.status, "unsupported")
        finally:
            manager.close()

    def test_unsupported_protocol_is_skipped(self) -> None:
        manager = self.make_manager(module_name="auxiliary/scanner/ping", protocol="icmp")
        try:
            job_id = manager.submit(self.approved_request("auxiliary/scanner/ping", protocol="icmp"))
            job = manager.wait(job_id, timeout=1)
            self.assertEqual(job.status, "skipped")
        finally:
            manager.close()

    def test_failed_module_is_classified(self) -> None:
        manager = self.make_manager(module_name="auxiliary/scanner/fail")
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

    def test_approval_store_failure_blocks_submission(self) -> None:
        class FailingApprovalStore:
            def get_approval(self, action_id: str) -> ActionApproval | None:
                raise sqlite3.OperationalError("database unavailable")

        manager = JobManager(
            ScopePolicy(networks=(ip_network("192.168.56.0/24"),)),
            approval_store=FailingApprovalStore(),
        )
        try:
            with self.assertRaisesRegex(JobError, "could not be verified"):
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

    def test_approval_for_different_risk_blocks_submission(self) -> None:
        manager = self.make_manager()
        try:
            with self.assertRaisesRegex(JobError, "does not match"):
                manager.submit(self.approved_request(risk="intrusive"))
        finally:
            manager.close()

    def test_revoked_approval_is_rechecked_before_adapter_dispatch(self) -> None:
        approval_store = MemoryApprovalStore(revoke_after_submit=True)
        manager = JobManager(
            ScopePolicy(networks=(ip_network("192.168.56.0/24"),)),
            approval_store=approval_store,
        )
        try:
            job_id = manager.submit(self.approved_request())
            job = manager.wait(job_id, timeout=1)
            self.assertEqual(job.status, "failed")
            self.assertEqual(job.error, "authorization-failed")
            self.assertIn("does not match", manager.events(job_id)[-1].message)
        finally:
            manager.close()

    def test_out_of_scope_target_is_rejected(self) -> None:
        manager = self.make_manager(target="192.168.57.10")
        try:
            with self.assertRaisesRegex(JobError, "outside"):
                manager.submit(self.approved_request(target="192.168.57.10"))
        finally:
            manager.close()
