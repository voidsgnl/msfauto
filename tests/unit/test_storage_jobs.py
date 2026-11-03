import tempfile
import unittest
from pathlib import Path

from msfauto.storage import WorkspaceStore
from msfauto.storage.models import CheckJob, JobEvent


class JobStorageTests(unittest.TestCase):
    def test_jobs_and_events_are_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = WorkspaceStore(Path(directory) / "state.sqlite3")
            job = CheckJob("job-1", "lab", "192.168.56.10", 22, "tcp", "scanner/example", "unsupported", "now")
            event = JobEvent("job-1", "now", "warning", "No adapter")
            store.save_job(job)
            store.save_job_event(event)

            self.assertEqual(store.get_jobs("lab"), (job,))
            self.assertEqual(store.get_job_events("job-1"), (event,))
