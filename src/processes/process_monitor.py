import time
import os
import psutil
from collections import defaultdict


class ProcessMonitor:
    """
    Monitors running processes, extracts execution metrics, tracks parent-child relationships,
    and builds lightweight in-memory behavioral profiles.
    """

    SUSPICIOUS_SPAWNS = {
        "winword.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
        "excel.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
        "powerpnt.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"},
        "outlook.exe": {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"},
        "acrord32.exe": {"cmd.exe", "powershell.exe"},
    }

    SUSPICIOUS_CHILDREN = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"}

    def __init__(self):
        # In-memory profile: proc_name -> {executions: int, cpu_samples: list, max_children: int, first_seen: float}
        self._profiles = defaultdict(lambda: {
            "executions": 0,
            "cpu_samples": [],
            "max_children": 0,
            "first_seen": time.time()
        })

    def _resolve_parent_name(self, ppid):
        if not ppid:
            return None
        try:
            parent_proc = psutil.Process(ppid)
            return parent_proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    def get_running_processes(self):
        """
        Retrieves active processes with detailed telemetry. Parent names are resolved lazily
        only when the process name matches suspicious child processes.
        """
        process_list = []
        attrs = ['pid', 'name', 'cpu_percent', 'memory_info', 'status', 'ppid', 'exe', 'num_threads']

        for proc in psutil.process_iter(attrs):
            try:
                info = proc.info
                mem_rss = info['memory_info'].rss / (1024 * 1024) if info['memory_info'] else 0.0
                pid = info['pid']
                name = info['name'] or "Unknown"
                ppid = info.get('ppid')
                exe = info.get('exe')
                threads = info.get('num_threads') or 1
                cpu_pct = info.get('cpu_percent') or 0.0

                # Lazy parent resolution: only resolve parent process for suspicious child candidates
                parent_name = None
                if ppid and name.lower() in self.SUSPICIOUS_CHILDREN:
                    parent_name = self._resolve_parent_name(ppid)

                process_list.append({
                    "pid": pid,
                    "name": name,
                    "cpu_percent": cpu_pct,
                    "memory_rss_mb": round(mem_rss, 2),
                    "status": info['status'] or "unknown",
                    "parent_pid": ppid,
                    "parent_name": parent_name,
                    "exe_path": exe,
                    "num_threads": threads
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return process_list

    def record_process_start(self, proc_dict):
        """Updates the behavioral profile for a newly spawned process."""
        name = proc_dict["name"].lower()
        prof = self._profiles[name]
        prof["executions"] += 1
        if proc_dict.get("cpu_percent"):
            prof["cpu_samples"].append(proc_dict["cpu_percent"])
            if len(prof["cpu_samples"]) > 50:
                prof["cpu_samples"].pop(0)

    def check_spawn_anomaly(self, proc_dict):
        """
        Stage A rule check: inspects parent-child relationship for known suspicious chains.
        Resolves parent name lazily if not already present.
        """
        child_name = (proc_dict.get("name") or "").lower()
        parent_name = (proc_dict.get("parent_name") or "").lower()

        if not parent_name and proc_dict.get("parent_pid") and child_name in self.SUSPICIOUS_CHILDREN:
            resolved = self._resolve_parent_name(proc_dict["parent_pid"])
            if resolved:
                parent_name = resolved.lower()
                proc_dict["parent_name"] = resolved

        if parent_name in self.SUSPICIOUS_SPAWNS:
            if child_name in self.SUSPICIOUS_SPAWNS[parent_name]:
                return True, f"Suspicious child process '{child_name}' spawned by document viewer '{parent_name}'"

        return False, None

    def get_profile(self, process_name):
        name = process_name.lower()
        if name in self._profiles:
            prof = self._profiles[name]
            avg_cpu = (sum(prof["cpu_samples"]) / len(prof["cpu_samples"])) if prof["cpu_samples"] else 0.0
            return {
                "name": process_name,
                "executions": prof["executions"],
                "avg_cpu_percent": round(avg_cpu, 1),
                "first_seen": prof["first_seen"]
            }
        return None

    def get_heavy_hitters(self, limit=5, cpu_threshold=50.0, ram_threshold_mb=500.0):
        all_procs = self.get_running_processes()
        heavy_cpu = sorted(
            [p for p in all_procs if p['cpu_percent'] > cpu_threshold],
            key=lambda x: x['cpu_percent'],
            reverse=True
        )[:limit]

        heavy_ram = sorted(
            [p for p in all_procs if p['memory_rss_mb'] > ram_threshold_mb],
            key=lambda x: x['memory_rss_mb'],
            reverse=True
        )[:limit]

        return heavy_cpu, heavy_ram
