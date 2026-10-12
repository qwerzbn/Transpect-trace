import json
import threading
from datetime import datetime, timezone
from transpect_trace.core.storage import atomic_write
from transpect_trace.normalization import normalize_run
from transpect_trace.reporting import project_report, report_path
from transpect_trace.tree_export import export_data


class RunLiveWriter:
    def __init__(self, root, interval=3):
        self.root, self.interval = root, interval
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.revision, self.fingerprint = 0, None
        self.destination = report_path(root).parent / 'live'

    def update(self):
        fingerprint = tuple((str(p), p.stat().st_size, p.stat().st_mtime_ns)
                            for p in sorted((self.root / 'raw').rglob('*')) if p.is_file())
        if fingerprint == self.fingerprint:
            return
        events = normalize_run(self.root, write=False)
        data = project_report(self.root, event_rows=[e.model_dump(mode='json') for e in events])
        self.revision += 1
        data['revision'] = self.revision
        export_data(data, self.destination)
        with (self.destination / 'updates.jsonl').open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(dict(revision=self.revision, events=len(events), time=datetime.now(timezone.utc).isoformat())) + '\n')
        self.fingerprint = fingerprint
        (self.destination / 'listener-error.json').unlink(missing_ok=True)

    def run(self):
        while not self.stop_event.is_set():
            try:
                self.update()
            except Exception as error:
                atomic_write(self.destination / 'listener-error.json', json.dumps(dict(error=str(error))).encode())
            self.stop_event.wait(self.interval)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.thread.join()
