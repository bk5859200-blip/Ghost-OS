import time
import psutil


class SystemSensor:
    """
    Gathers hardware resource utilization, process count, uptime, and I/O rates.
    Stateful implementation to calculate network and disk throughput rates accurately.
    """

    def __init__(self):
        self.last_time = time.time()

        # Initialize Disk I/O counters
        disk_io = psutil.disk_io_counters()
        self.last_disk_read = disk_io.read_bytes if disk_io else 0
        self.last_disk_write = disk_io.write_bytes if disk_io else 0

        # Initialize Network I/O counters
        net_io = psutil.net_io_counters()
        self.last_net_sent = net_io.bytes_sent if net_io else 0
        self.last_net_recv = net_io.bytes_recv if net_io else 0

    def get_system_uptime_seconds(self):
        """Calculates system uptime in seconds."""
        try:
            return int(time.time() - psutil.boot_time())
        except Exception:
            return 0

    def collect_metrics(self):
        """
        Gathers system hardware resource utilization.
        :return: dict with telemetry metrics
        """
        current_time = time.time()
        time_delta = current_time - self.last_time
        if time_delta <= 0:
            time_delta = 0.001

        # CPU & Memory
        cpu_percent = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory()
        ram_percent = ram.percent
        available_ram_mb = round(ram.available / (1024 * 1024), 1)

        # Disk
        try:
            disk_usage = psutil.disk_usage('C:\\')
            disk_used_percent = disk_usage.percent
            disk_free_gb = round(disk_usage.free / (1024 * 1024 * 1024), 2)
        except Exception:
            disk_used_percent = 0.0
            disk_free_gb = 0.0

        # I/O Counters
        disk_io = psutil.disk_io_counters()
        curr_disk_read = disk_io.read_bytes if disk_io else 0
        curr_disk_write = disk_io.write_bytes if disk_io else 0

        net_io = psutil.net_io_counters()
        curr_net_sent = net_io.bytes_sent if net_io else 0
        curr_net_recv = net_io.bytes_recv if net_io else 0

        # Throughput rates (MB/s)
        disk_read_rate = ((curr_disk_read - self.last_disk_read) / time_delta) / (1024 * 1024)
        disk_write_rate = ((curr_disk_write - self.last_disk_write) / time_delta) / (1024 * 1024)
        net_sent_rate = ((curr_net_sent - self.last_net_sent) / time_delta) / (1024 * 1024)
        net_recv_rate = ((curr_net_recv - self.last_net_recv) / time_delta) / (1024 * 1024)

        # Update cache state
        self.last_time = current_time
        self.last_disk_read = curr_disk_read
        self.last_disk_write = curr_disk_write
        self.last_net_sent = curr_net_sent
        self.last_net_recv = curr_net_recv

        # Process count & Uptime
        try:
            process_count = len(psutil.pids())
        except Exception:
            process_count = 0

        uptime_seconds = self.get_system_uptime_seconds()

        return {
            "cpu_percent": cpu_percent,
            "ram_percent": ram_percent,
            "available_ram_mb": available_ram_mb,
            "disk_used_percent": disk_used_percent,
            "disk_free_gb": disk_free_gb,
            "disk_read_rate_mb": round(disk_read_rate, 2),
            "disk_write_rate_mb": round(disk_write_rate, 2),
            "net_sent_rate_mb": round(net_sent_rate, 2),
            "net_recv_rate_mb": round(net_recv_rate, 2),
            "process_count": process_count,
            "uptime_seconds": uptime_seconds
        }
