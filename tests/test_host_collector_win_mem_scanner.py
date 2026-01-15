import os
import sys
import logging
import time

# === Path Setup ===
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import the actual library to test
try:
    from collector.host_collector.win_mem_scanner import WinMemoryScanner
except ImportError as e:
    print(f"CRITICAL: Failed to import WinMemoryScanner. Error: {e}")
    sys.exit(1)

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("TestWinMemScanner")

def run_test():
    """
    Test the WinMemoryScanner by scanning the current process (Self-Scan).
    This verifies that the ctypes calls and logic are working without crashing.
    """
    logger.info("Initializing WinMemoryScanner...")
    try:
        scanner = WinMemoryScanner()
    except Exception as e:
        logger.error(f"Failed to initialize scanner: {e}")
        return

    pid = os.getpid()
    logger.info(f"Starting self-scan on PID {pid}...")
    
    start_time = time.time()
    try:
        anomalies = scanner.scan_pid(pid)
        duration = time.time() - start_time
        
        logger.info(f"Scan finished in {duration:.4f}s")
        
        if anomalies:
            logger.warning(f"Unexpected anomalies found in self (Test Script): {len(anomalies)}")
            for a in anomalies:
                logger.info(f" - {a}")
        else:
            logger.info("Self-scan clean. Scanner is functioning correctly.")
            
    except Exception as e:
        logger.error(f"Scan failed with exception: {e}")
        raise

if __name__ == "__main__":
    run_test()
