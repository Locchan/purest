import itertools
import threading
from socketserver import ThreadingMixIn


class NamedThreadingMixIn(ThreadingMixIn):
    """ThreadingMixIn whose workers are named PREFIX#N instead of Thread-N."""

    thread_prefix = "W#"
    # None = unlimited concurrent request threads; int = BoundedSemaphore limit.
    max_workers: int | None = None

    def process_request(self, request, client_address):
        limit = getattr(self, "max_workers", None)
        if limit is not None:
            sem = vars(self).setdefault("_purest_worker_sem", threading.BoundedSemaphore(int(limit)))
            sem.acquire()
        else:
            sem = None

        seq = vars(self).setdefault("_purest_worker_seq", itertools.count(1))
        if self.block_on_close:
            from socketserver import _Threads

            vars(self).setdefault("_threads", _Threads())

        def run():
            try:
                self.process_request_thread(request, client_address)
            finally:
                if sem is not None:
                    sem.release()

        worker = threading.Thread(
            target=run,
            name=f"{self.thread_prefix}{next(seq)}",
            daemon=self.daemon_threads,
        )
        self._threads.append(worker)
        worker.start()
