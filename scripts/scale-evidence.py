"""Pure bounded measurements for the disposable installed scale/soak fixture."""
import math
import re

KINDS = {"HankoApplication": "hankoapplication", "HankoRole": "hankorole", "HankoOrganization": "hankoorganization",
         "HankoResourceServer": "hankoresourceserver", "HankoRealm": "hankorealm"}
WORKER_KINDS = set(KINDS) - {"HankoRealm"}
COUNTERS = {"rest_client_requests_total": "api_requests", "hanko_operator_provider_requests_total": "provider_requests",
            "process_cpu_seconds_total": "cpu_seconds"}
GAUGES = {"process_resident_memory_bytes": "rss_bytes", "go_memstats_heap_alloc_bytes": "heap_bytes",
          "go_goroutines": "goroutines", "process_start_time_seconds": "process_started", "hanko_operator_leader": "leader"}
LINE = re.compile(r"([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^\n]*)\})?\s+([^\s]+)(?:\s+[0-9]+)?")


def sampling_gap(previous, current):
    gap = current - previous
    if not math.isfinite(gap) or not 0 <= gap <= 45:
        raise ValueError("Continuous measurement lost its 45-second sampling bound")
    return gap


def label(labels, key):
    match = re.search(r'(?:^|,)' + key + r'="([A-Za-z0-9_.+-]+)"(?:,|$)', labels)
    return match[1] if match else None


def metrics(text):
    if len(text.encode()) > 2 * 1024**2:
        raise ValueError("Metrics exceed fixture budget")
    result = {"reconciles": {}, "workers": {}, "active": {}, "latency": {}}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        match = LINE.fullmatch(line)
        if not match:
            raise ValueError("Malformed metrics response")
        name, labels, raw = match[1], match[2] or "", match[3]
        if name not in COUNTERS and name not in GAUGES and name not in (
                "hanko_operator_reconcile_total", "controller_runtime_max_concurrent_reconciles", "controller_runtime_active_workers",
                "hanko_operator_reconcile_duration_seconds_bucket"):
            continue
        try:
            value = float(raw)
        except ValueError:
            raise ValueError("Invalid numeric metric; response withheld") from None
        if not math.isfinite(value) or value < 0:
            raise ValueError("Non-finite or negative measurement")
        if name in COUNTERS:
            key = COUNTERS[name]
            result[key] = result.get(key, 0) + value
        elif name in GAUGES:
            result[GAUGES[name]] = value
        elif name == "hanko_operator_reconcile_total":
            kind = label(labels, "kind")
            if kind in KINDS:
                result["reconciles"][kind] = result["reconciles"].get(kind, 0) + value
        elif name == "hanko_operator_reconcile_duration_seconds_bucket":
            kind, bound = label(labels, "kind"), label(labels, "le")
            if kind in KINDS and bound:
                buckets = result["latency"].setdefault(kind, {})
                buckets[bound] = buckets.get(bound, 0) + value
        else:
            controller = label(labels, "controller")
            if controller in KINDS.values():
                key = "workers" if "max_concurrent" in name else "active"
                result[key][controller] = value
    required = {"rss_bytes", "process_started", "api_requests", "provider_requests", "leader"}
    if not required <= set(result) or result["leader"] not in (0, 1):
        raise ValueError("Required process/provider/API/leader metrics are missing")
    return result


def quantile_upper_bound(buckets, quantile=.95):
    total = buckets.get("+Inf", 0)
    if total == 0:
        return None
    try:
        ordered = sorted(buckets.items(), key=lambda item: float(item[0]))
    except ValueError:
        raise ValueError("Invalid histogram bound") from None
    previous = 0
    for _, count in ordered:
        if count < previous or count > total:
            raise ValueError("Histogram is not cumulative")
        previous = count
    for bound, count in ordered:
        if count >= total * quantile:
            return float(bound) if math.isfinite(float(bound)) else None
    raise ValueError("Histogram is incomplete")


class Ledger:
    """Track process epochs; never treat disappeared counters as a zero sample."""
    def __init__(self):
        self.last = {}
        self.counters = {name: 0 for name in COUNTERS.values()}
        self.reconciles, self.latency, self.peak_workers = {}, {}, {}
        self.rss_peak, self.frames = 0, 0
        self.current_processes = set()
        self.lost_processes = 0

    def observe(self, frames, workers):
        if not frames or sum(frame["leader"] for frame in frames.values()) != 1:
            raise ValueError("A measured sample requires exactly one observed leader")
        current = set()
        rss = heap = goroutines = 0
        for uid, frame in frames.items():
            epoch = (uid, frame["process_started"])
            current.add(epoch)
            old = self.last.get(epoch, {})
            for key in self.counters:
                value, previous = frame.get(key, 0), old.get(key, 0)
                if value < previous:
                    raise ValueError("A counter reset without a new process epoch")
                self.counters[key] += value - previous
            for kind, value in frame["reconciles"].items():
                previous = old.get("reconciles", {}).get(kind, 0)
                if value < previous:
                    raise ValueError("Reconcile counter reset")
                self.reconciles[kind] = self.reconciles.get(kind, 0) + value - previous
            for kind, buckets in frame["latency"].items():
                target = self.latency.setdefault(kind, {})
                for bound, value in buckets.items():
                    previous = old.get("latency", {}).get(kind, {}).get(bound, 0)
                    if value < previous:
                        raise ValueError("Histogram counter reset")
                    target[bound] = target.get(bound, 0) + value - previous
            for kind in WORKER_KINDS:
                controller = KINDS[kind]
                if frame["leader"] and frame["workers"].get(controller) != workers:
                    raise ValueError("Installed controller workers differ from requested configuration")
                active = frame["active"].get(controller, 0)
                if active > workers:
                    raise ValueError("Observed workers exceed configured concurrency")
                self.peak_workers[kind] = max(self.peak_workers.get(kind, 0), active)
            rss += frame["rss_bytes"]
            heap += frame.get("heap_bytes", 0)
            goroutines += frame.get("goroutines", 0)
            self.last[epoch] = frame
        self.lost_processes += len(self.current_processes - current)
        self.current_processes = current
        self.rss_peak = max(self.rss_peak, rss)
        self.frames += 1
        return {"sample": self.frames, "rss_bytes": rss, "rss_peak_bytes": self.rss_peak,
                "heap_bytes": heap, "goroutines": goroutines,
                "api_requests": self.counters["api_requests"], "provider_requests": self.counters["provider_requests"],
                "cpu_seconds": self.counters["cpu_seconds"], "reconciles": dict(self.reconciles),
                "peak_workers": dict(self.peak_workers), "lost_processes": self.lost_processes}

    def checkpoint(self):
        return {"counters": dict(self.counters), "reconciles": dict(self.reconciles),
                "latency": {k: dict(v) for k, v in self.latency.items()}, "lost_processes": self.lost_processes, "frames": self.frames}

    def require_continuity(self, before):
        if self.lost_processes != before["lost_processes"]:
            raise ValueError("A steady-state process disappeared; counters are incomplete")

    def window(self, before, seconds, counts):
        if seconds < 1 or self.frames - before["frames"] < 2:
            raise ValueError("Insufficient measured interval")
        attempts = {kind: self.reconciles.get(kind, 0) - before["reconciles"].get(kind, 0) for kind in counts}
        # Two edge periods plus a generous dependency-event allowance. This
        # catches status-driven hot loops, not slow provider throughput.
        ceilings = {kind: max(10, count * (seconds / 30 + 2) * 3) for kind, count in counts.items()}
        if any(attempts[kind] > ceilings[kind] for kind in counts):
            raise ValueError("Steady-state reconciliation exceeds the hot-loop bound")
        self.require_continuity(before)
        latency = {}
        for kind, buckets in self.latency.items():
            delta = {bound: count - before["latency"].get(kind, {}).get(bound, 0) for bound, count in buckets.items()}
            latency[kind] = {"observations": delta.get("+Inf", 0), "p95_upper_bound_seconds": quantile_upper_bound(delta)}
        return {"seconds": round(seconds, 3), "samples": self.frames - before["frames"], "counter_completeness": True,
                "api_request_starts_per_second": (self.counters["api_requests"] - before["counters"]["api_requests"]) / seconds,
                "provider_requests_per_second": (self.counters["provider_requests"] - before["counters"]["provider_requests"]) / seconds,
                "reconciles": attempts, "hot_loop_ceiling": ceilings, "reconcile_latency": latency,
                "rss_peak_bytes": self.rss_peak, "observed_peak_workers": dict(self.peak_workers)}
