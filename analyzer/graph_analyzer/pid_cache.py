# analyzer/graph_analyzer/pid_cache.py
"""
PID 上下文缓存 v5.1

功能：
  解决 Linux PID 复用问题。通过缓存 (Host, PID) -> StartTime 的映射，
  确保即使 PID 被复用，也能生成唯一的节点 ID。

存储策略：
  - 内存缓存 + 本地 JSON 文件持久化
  - 批量写入：积累 N 条后再写文件，避免 I/O 爆炸
  - 原子写入：先写临时文件，再 rename，防止崩溃导致文件损坏

使用示例：
    cache = PIDCache()
    cache.set_start_time("host1", 1234, "2026-01-14T10:00:00Z")
    start_time = cache.get_start_time("host1", 1234)
"""
import json
import os
import tempfile
import atexit
import logging
from typing import Optional, Dict
from threading import Lock

logger = logging.getLogger(__name__)

# 默认缓存文件路径（相对于工作目录）
DEFAULT_CACHE_FILE = "pid_context_cache.json"
# 批量写入阈值：每 100 次修改后写入一次
BATCH_WRITE_THRESHOLD = 100


class PIDCache:
    """
    PID 上下文缓存器
    
    线程安全，支持批量写入和原子持久化。
    """
    
    def __init__(self, cache_file: str = DEFAULT_CACHE_FILE):
        """
        初始化缓存
        
        Args:
            cache_file: 缓存文件路径，默认为当前目录下的 pid_context_cache.json
        """
        self.cache_file = cache_file
        self.cache: Dict[str, str] = {}
        self._dirty_count = 0  # 未持久化的修改计数
        self._lock = Lock()    # 线程锁
        
        # 从文件加载已有缓存
        self._load()
        
        # 注册退出时自动刷盘
        atexit.register(self._flush)
        
    def _load(self) -> None:
        """从文件加载缓存数据"""
        if not os.path.exists(self.cache_file):
            logger.info(f"PIDCache: No existing cache file at {self.cache_file}")
            return
            
        try:
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                self.cache = json.load(f)
            logger.info(f"PIDCache: Loaded {len(self.cache)} entries from {self.cache_file}")
        except json.JSONDecodeError as e:
            logger.warning(f"PIDCache: Cache file corrupted, starting fresh. Error: {e}")
            self.cache = {}
        except Exception as e:
            logger.error(f"PIDCache: Failed to load cache: {e}")
            self.cache = {}
    
    def _make_key(self, host: str, pid: int) -> str:
        """生成缓存键"""
        return f"{host}_{pid}"
    
    def set_start_time(self, host: str, pid: int, start_time: str) -> None:
        """
        设置进程启动时间
        
        Args:
            host: 主机名
            pid: 进程 ID
            start_time: 启动时间字符串（ISO8601 格式）
        """
        key = self._make_key(host, pid)
        
        with self._lock:
            # 只有值变化时才标记为脏数据
            if self.cache.get(key) != start_time:
                self.cache[key] = start_time
                self._dirty_count += 1
                
                # 达到阈值时批量写入
                if self._dirty_count >= BATCH_WRITE_THRESHOLD:
                    self._flush_unsafe()  # 已持有锁，使用无锁版本
    
    def get_start_time(self, host: str, pid: int) -> Optional[str]:
        """
        获取进程启动时间
        
        Args:
            host: 主机名
            pid: 进程 ID
            
        Returns:
            启动时间字符串，如果不存在则返回 None
        """
        key = self._make_key(host, pid)
        return self.cache.get(key)
    
    def _flush_unsafe(self) -> None:
        """
        将缓存写入文件（无锁版本，调用者需持有锁）
        
        使用原子写入策略：先写临时文件，再 rename。
        """
        if self._dirty_count == 0:
            return
            
        try:
            # 获取缓存文件所在目录
            cache_dir = os.path.dirname(self.cache_file) or '.'
            
            # 创建临时文件并写入
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.json',
                dir=cache_dir,
                delete=False,
                encoding='utf-8'
            ) as tf:
                json.dump(self.cache, tf, indent=2, ensure_ascii=False)
                temp_path = tf.name
            
            # 原子替换（Windows 上需要先删除目标文件）
            if os.name == 'nt' and os.path.exists(self.cache_file):
                os.remove(self.cache_file)
            os.rename(temp_path, self.cache_file)
            
            logger.debug(f"PIDCache: Flushed {self._dirty_count} entries to {self.cache_file}")
            self._dirty_count = 0
            
        except Exception as e:
            logger.error(f"PIDCache: Failed to flush cache: {e}")
            # 尝试清理临时文件
            if 'temp_path' in locals() and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass
    
    def _flush(self) -> None:
        """将缓存写入文件（线程安全版本）"""
        with self._lock:
            self._flush_unsafe()
    
    def flush(self) -> None:
        """
        强制刷盘（公开 API）
        
        在关键时刻（如处理完一批事件）手动调用。
        """
        self._flush()
    
    def clear(self) -> None:
        """清空缓存（用于测试）"""
        with self._lock:
            self.cache.clear()
            self._dirty_count = 0
            if os.path.exists(self.cache_file):
                os.remove(self.cache_file)
                logger.info(f"PIDCache: Cleared cache and removed {self.cache_file}")
    
    def size(self) -> int:
        """返回缓存条目数"""
        return len(self.cache)
    
    def __len__(self) -> int:
        return self.size()
    
    def __repr__(self) -> str:
        return f"<PIDCache entries={self.size()} dirty={self._dirty_count}>"
