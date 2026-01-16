import os
import sys
import shutil
from pathlib import Path

# Add project root to sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

def cleanup():
    print("🚀 Starting Unified APT Data Cleanup...")
    
    # 1. Delete Active Simulation Markers (The "Switches")
    active_dir = Path(project_root) / "web" / "backend" / "active_simulations"
    if active_dir.exists():
        print(f"[*] Cleaning up active markers in {active_dir}...")
        count = 0
        for file in active_dir.glob("*"):
            if file.is_file():
                try:
                    file.unlink()
                    print(f"    - Deleted marker: {file.name}")
                    count += 1
                except Exception as e:
                    print(f"    ❌ Failed to delete {file.name}: {e}")
        print(f"    ✅ Removed {count} active markers.")
    else:
        print("[*] No active markers directory found.")

    # 2. Delete Cached APT Reports
    cache_dir = Path(project_root) / "web" / "backend" / "cache"
    if cache_dir.exists():
        print(f"[*] Cleaning up cached reports in {cache_dir}...")
        count = 0
        # Delete only APT reports to avoid deleting other cache
        for file in cache_dir.glob("apt_report_*.json"):
            try:
                file.unlink()
                print(f"    - Deleted cache: {file.name}")
                count += 1
            except Exception as e:
                print(f"    ❌ Failed to delete {file.name}: {e}")
        print(f"    ✅ Removed {count} cached reports.")
    else:
        print("[*] No cache directory found.")

    print("\n🏁 Cleanup complete. The APT switches should now be gone from the Web UI.")
    print("   (Note: Data ingested into Elasticsearch remains until index rotation or manual deletion)")

if __name__ == "__main__":
    cleanup()
