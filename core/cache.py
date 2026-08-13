"""Result caching system to avoid redundant scans."""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from core.config import get_settings
from core.logger import get_logger
from core.models import ScanResult

logger = get_logger("core.cache")


class CacheEntry(BaseModel):
    """Cached scan result."""
    target: str
    modules: list[str]
    result_data: dict
    created_at: datetime
    expires_at: datetime
    checksum: str

    def is_expired(self) -> bool:
        """Check if cache entry has expired."""
        return datetime.now(timezone.utc) >= self.expires_at

    # No __hash__: it used to return the checksum string, so hash(entry) raised
    # TypeError and nothing could actually hash an entry. Nothing needs to —
    # entries are dict values keyed by cache key — so the method is gone rather
    # than repaired, which also keeps __eq__/__hash__ consistent (pydantic
    # supplies field equality).


class ScanCache:
    """Manages caching of scan results."""

    DEFAULT_TTL = 24 * 3600  # 24 hours in seconds

    def __init__(self, ttl_seconds: int = DEFAULT_TTL):
        """Initialize cache.

        Args:
            ttl_seconds: Time-to-live for cache entries in seconds
        """
        self.ttl = ttl_seconds
        self.cache_dir = get_settings().data_dir / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._memory_cache: dict[str, CacheEntry] = {}
        logger.info(f"Initialized scan cache with TTL={ttl_seconds}s at {self.cache_dir}")

    @staticmethod
    def _compute_checksum(
        target: str,
        modules: list[str],
        options: dict[str, Any] = None,
    ) -> str:
        """Compute checksum for cache key.

        Args:
            target: Target string
            modules: Modules to run
            options: Module options

        Returns:
            Hex checksum string
        """
        key_data = {
            "target": target,
            "modules": sorted(modules),
            "options": options or {},
        }
        key_str = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(key_str.encode()).hexdigest()

    def _get_cache_path(self, checksum: str) -> Path:
        """Get cache file path for checksum.

        Args:
            checksum: Cache checksum

        Returns:
            Path to cache file
        """
        return self.cache_dir / f"{checksum}.json"

    def get(
        self,
        target: str,
        modules: list[str],
        options: dict[str, Any] = None,
    ) -> ScanResult | None:
        """Retrieve cached scan result if available and not expired.

        Args:
            target: Target string
            modules: Modules that were run
            options: Module options used

        Returns:
            Cached ScanResult if available and valid, None otherwise
        """
        checksum = self._compute_checksum(target, modules, options)

        # Check memory cache first
        if checksum in self._memory_cache:
            entry = self._memory_cache[checksum]
            if not entry.is_expired():
                logger.debug(f"Cache HIT (memory) for {target}")
                return ScanResult(**entry.result_data)
            else:
                # Remove expired entry
                del self._memory_cache[checksum]
                logger.debug(f"Cache entry expired for {target}")

        # Check disk cache
        cache_path = self._get_cache_path(checksum)
        if cache_path.exists():
            try:
                with open(cache_path) as f:
                    data = json.load(f)
                    entry = CacheEntry(**data)

                    if not entry.is_expired():
                        logger.debug(f"Cache HIT (disk) for {target}")
                        # Restore to memory cache
                        self._memory_cache[checksum] = entry
                        return ScanResult(**entry.result_data)
                    else:
                        # Remove expired file
                        cache_path.unlink()
                        logger.debug(f"Deleted expired cache file for {target}")
            except Exception as e:
                logger.warning(f"Error reading cache file {cache_path}: {e}")

        logger.debug(f"Cache MISS for {target}")
        return None

    def set(
        self,
        target: str,
        modules: list[str],
        result: ScanResult,
        options: dict[str, Any] = None,
    ) -> None:
        """Cache scan result.

        Args:
            target: Target string
            modules: Modules that were run
            result: ScanResult to cache
            options: Module options used
        """
        checksum = self._compute_checksum(target, modules, options)
        now = datetime.now(timezone.utc)

        entry = CacheEntry(
            target=target,
            modules=modules,
            result_data=result.model_dump(),
            created_at=now,
            expires_at=now + timedelta(seconds=self.ttl),
            checksum=checksum,
        )

        # Store in memory cache
        self._memory_cache[checksum] = entry

        # Store on disk
        cache_path = self._get_cache_path(checksum)
        try:
            with open(cache_path, 'w') as f:
                json.dump(entry.model_dump(), f, default=str, indent=2)
                logger.debug(f"Cached result for {target} (checksum={checksum[:8]})")
        except Exception as e:
            logger.error(f"Error writing cache file {cache_path}: {e}")

    def clear(self, target: str | None = None) -> int:
        """Clear cache entries.

        Args:
            target: Specific target to clear, or None to clear all

        Returns:
            Number of entries cleared
        """
        cleared_checksums: set[str] = set()

        # Clear memory cache
        if target:
            keys_to_delete = [
                k for k, v in self._memory_cache.items()
                if v.target == target
            ]
            for k in keys_to_delete:
                del self._memory_cache[k]
                cleared_checksums.add(k)
        else:
            cleared_checksums.update(self._memory_cache.keys())
            self._memory_cache.clear()

        # Clear disk cache
        try:
            for cache_file in self.cache_dir.glob("*.json"):
                if target:
                    with open(cache_file) as f:
                        data = json.load(f)
                        if data.get("target") == target:
                            cache_file.unlink()
                            cleared_checksums.add(cache_file.stem)
                else:
                    cache_file.unlink()
                    cleared_checksums.add(cache_file.stem)
        except Exception as e:
            logger.error(f"Error clearing disk cache: {e}")

        cleared = len(cleared_checksums)
        logger.info(f"Cleared {cleared} cache entries for target={target or 'all'}")
        return cleared

    def cleanup_expired(self) -> int:
        """Remove expired cache entries.

        Returns:
            Number of entries removed
        """
        removed = 0

        # Clean memory cache
        expired_keys = [
            k for k, v in self._memory_cache.items()
            if v.is_expired()
        ]
        for k in expired_keys:
            del self._memory_cache[k]
            removed += 1

        # Clean disk cache
        try:
            for cache_file in self.cache_dir.glob("*.json"):
                with open(cache_file) as f:
                    data = json.load(f)
                    entry = CacheEntry(**data)
                    if entry.is_expired():
                        cache_file.unlink()
                        removed += 1
        except Exception as e:
            logger.error(f"Error cleaning expired cache: {e}")

        if removed > 0:
            logger.info(f"Removed {removed} expired cache entries")

        return removed

    def get_stats(self) -> dict:
        """Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        memory_entries = len(self._memory_cache)

        disk_entries = 0
        try:
            disk_entries = len(list(self.cache_dir.glob("*.json")))
        except Exception as e:
            logger.error(f"Error counting disk cache: {e}")

        total_entries = max(memory_entries, disk_entries)

        return {
            "memory_entries": memory_entries,
            "disk_entries": disk_entries,
            "total_entries": total_entries,
            "cache_directory": str(self.cache_dir),
            "ttl_seconds": self.ttl,
        }


# Global cache instance
_cache_instance: ScanCache | None = None


def get_cache(ttl_seconds: int = ScanCache.DEFAULT_TTL) -> ScanCache:
    """Get or create global cache instance.

    Args:
        ttl_seconds: Time-to-live for cache entries

    Returns:
        ScanCache instance
    """
    global _cache_instance

    if _cache_instance is None:
        _cache_instance = ScanCache(ttl_seconds)

    return _cache_instance
