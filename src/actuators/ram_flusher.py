import ctypes
import psutil

class RAMFlusher:
    """
    Interacts with the Windows kernel to force processes to release their working physical memory.
    Swaps inactive physical RAM pages to the Windows pagefile (working set trimming).
    """
    def __init__(self):
        # OpenProcess flags
        self.PROCESS_QUERY_INFORMATION = 0x0400
        self.PROCESS_SET_QUOTA = 0x0100

    def trim_process(self, pid):
        """
        Trims the working memory set of a single process.
        :param pid: Process Identifier
        :return: True if successful, False otherwise
        """
        try:
            handle = ctypes.windll.kernel32.OpenProcess(
                self.PROCESS_QUERY_INFORMATION | self.PROCESS_SET_QUOTA,
                False,
                pid
            )
            if handle:
                # Flush the memory
                success = ctypes.windll.psapi.EmptyWorkingSet(handle)
                ctypes.windll.kernel32.CloseHandle(handle)
                return bool(success)
        except Exception:
            # Silently fail if permissions are insufficient for this process
            pass
        return False

    def trim_all_user_processes(self):
        """
        Iterates over all user-owned processes and trims their memory.
        :return: Number of successfully optimized processes
        """
        count = 0
        for proc in psutil.process_iter(['pid', 'username']):
            try:
                # Avoid trimming core system services to maintain performance stability
                username = proc.info.get('username')
                if username and 'SYSTEM' not in username.upper() and 'LOCAL SERVICE' not in username.upper():
                    if self.trim_process(proc.info['pid']):
                        count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return count

if __name__ == "__main__":
    import time
    flusher = RAMFlusher()
    print("Capturing memory baseline...")
    mem_before = psutil.virtual_memory().available / (1024 * 1024)
    print(f"Available RAM: {mem_before:.2f} MB")
    
    print("Trimming working sets...")
    optimized_count = flusher.trim_all_user_processes()
    
    time.sleep(1)
    mem_after = psutil.virtual_memory().available / (1024 * 1024)
    print(f"Available RAM now: {mem_after:.2f} MB")
    print(f"Successfully trimmed {optimized_count} processes. Recovered: {mem_after - mem_before:.2f} MB")
