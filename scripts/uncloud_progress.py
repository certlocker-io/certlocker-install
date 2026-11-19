"""Human-readable, secret-free setup progress with a quiet-stage heartbeat."""
from contextlib import contextmanager
import threading
import time


def format_duration(seconds):
    """Format elapsed seconds for operator totals (1h 02m 05s / 12m 05s / 4.2s)."""
    seconds = max(0.0, float(seconds))
    whole = int(seconds)
    hours, rem = divmod(whole, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f'{hours}h {minutes:02d}m {secs:02d}s'
    if minutes:
        return f'{minutes}m {secs:02d}s'
    return f'{seconds:.1f}s'


class Progress:
    """Only the innermost open stage emits heartbeats; parents stay quiet.

    Call detail() during a long stage so operators see which sub-check is active
    instead of a repeating generic "Working" line. quiet() pauses heartbeats while
    hidden prompts are on the controlling terminal. finish() prints the wall-clock
    total for the whole setup/workflow.
    """

    current = None

    def __init__(self, operation='setup', interval=20):
        self.operation = operation
        self.interval = interval
        self.number = 0
        self.started = time.monotonic()
        self._finished = False
        self._lock = threading.Lock()
        self._stack = []
        self._prompting = 0
        Progress.current = self

    def elapsed_seconds(self):
        return time.monotonic() - self.started

    def finish(self, status='passed'):
        """Print once: total wall-clock time for this Progress instance."""
        if self._finished:
            return self.elapsed_seconds()
        self._finished = True
        elapsed = self.elapsed_seconds()
        label = {'passed': 'passed', 'failed': 'failed', 'stopped': 'stopped'}.get(status, status)
        steps = f'{self.number} step' + ('' if self.number == 1 else 's')
        print(
            f'[{self.operation}] Total time: {format_duration(elapsed)} '
            f'({steps}, {label})',
            flush=True,
        )
        return elapsed

    def detail(self, message):
        """Publish the current sub-step for the innermost stage."""
        with self._lock:
            if self._prompting:
                return
            if not self._stack:
                print(f'[{self.operation}] {message}', flush=True)
                return
            frame = self._stack[-1]
            frame['detail'] = message
            print(f"{frame['prefix']} {message}", flush=True)

    @contextmanager
    def quiet(self):
        """Pause heartbeats while the operator answers a terminal prompt."""
        with self._lock:
            self._prompting += 1
        try:
            yield
        finally:
            with self._lock:
                self._prompting = max(0, self._prompting - 1)

    def _heartbeat_line(self, frame, elapsed):
        detail = frame.get('detail')
        if detail:
            return (f"{frame['prefix']} Still running ({elapsed:.0f}s): {detail}")
        return (f"{frame['prefix']} Still running ({elapsed:.0f}s): {frame['description']} "
                f"— waiting on network or Trust; no failure reported yet")

    @contextmanager
    def stage(self, description):
        self.number += 1
        prefix = f'[{self.operation} · step {self.number}]'
        frame = {
            'prefix': prefix,
            'description': description,
            'detail': None,
            'started': time.monotonic(),
            'stopped': threading.Event(),
            'active': True,
        }
        with self._lock:
            for parent in self._stack:
                parent['active'] = False
            self._stack.append(frame)

        def heartbeat():
            while not frame['stopped'].wait(self.interval):
                with self._lock:
                    if self._prompting or not frame['active'] or frame is not self._stack[-1]:
                        continue
                    elapsed = time.monotonic() - frame['started']
                    line = self._heartbeat_line(frame, elapsed)
                print(line, flush=True)

        print(f'{prefix} Starting: {description}', flush=True)
        worker = threading.Thread(target=heartbeat, daemon=True)
        worker.start()
        status = 'Complete'
        try:
            yield self
        except BaseException:
            status = 'Failed'
            raise
        finally:
            frame['stopped'].set()
            worker.join(timeout=1)
            elapsed = time.monotonic() - frame['started']
            with self._lock:
                if self._stack and self._stack[-1] is frame:
                    self._stack.pop()
                if self._stack:
                    self._stack[-1]['active'] = True
            print(f'{prefix} {status}: {description} ({elapsed:.1f}s)', flush=True)


PLAY_LABELS = {
    'uncloud_bootstrap.yml': 'Secure Ubuntu, configure SSH/firewalls, and install Docker and Java',
    'uncloud_host_verify.yml': 'Check server access, operating system and security settings',
    'uncloud_network_verify.yml': 'Verify the private connection between both servers',
    'uncloud_apps_network.yml': 'Allow application traffic on the private mesh',
    'uncloud_database.yml': 'Start PostgreSQL, replication and database connection routing',
    'uncloud_database_verify.yml': 'Verify one writable database and its streaming replica',
    'uncloud_registry_auth.yml': 'Configure VM identity for private image downloads',
    'uncloud_apps_router_proxy.yml': 'Install the stable Router connection on both servers',
    'uncloud_apps.yml': 'Download and start the application release on both servers',
    'uncloud_runtime_secrets.yml': 'Encrypt the boot cache and keep live secrets in memory',
    'uncloud_apps_failover.yml': 'Install automatic recovery and failover monitoring',
    'uncloud_apps_verify.yml': 'Check application health and Router registrations',
    'uncloud_monitoring.yml': 'Start monitoring, metrics and alerts',
    'uncloud_certificate_automation.yml': 'Prepare certificate deployment access on both HAProxies',
    'uncloud_ingress.yml': 'Configure public HTTP and HTTPS entry points',
    'uncloud_ha_verify.yml': 'Verify HTTPS, recovery services and monitoring on both servers',
}
