"""Tests for cache functionality."""

from datetime import datetime, timedelta, timezone

import pytest

from core.cache import CacheEntry, ScanCache
from core.models import Finding, ScanResult, Severity, Target


@pytest.fixture
def temp_cache(tmp_path):
    """Create temporary cache for testing."""
    cache = ScanCache(ttl_seconds=3600)
    cache.cache_dir = tmp_path / "cache"
    cache.cache_dir.mkdir(parents=True, exist_ok=True)
    cache._memory_cache.clear()  # Clear memory cache before test
    # Clear any existing cache files
    for cache_file in cache.cache_dir.glob("*.json"):
        cache_file.unlink()
    yield cache
    cache._memory_cache.clear()  # Clear memory cache after test
    # Clean up cache files after test
    for cache_file in cache.cache_dir.glob("*.json"):
        cache_file.unlink()


@pytest.fixture
def sample_result():
    """Create sample ScanResult for testing."""
    target = Target.from_string("example.com")
    result = ScanResult(target=target, module="test")

    finding = Finding(
        title="Test Finding",
        description="Test description",
        severity=Severity.HIGH,
        source="test",
    )
    result.findings.append(finding)

    return result


class TestScanCache:
    """Tests for ScanCache."""

    def test_cache_set_and_get(self, temp_cache, sample_result):
        """Test setting and getting cache entries."""
        target = "example.com"
        modules = ["osint", "webscanner"]

        temp_cache.set(target, modules, sample_result)

        cached = temp_cache.get(target, modules)
        assert cached is not None
        assert cached.target.value == target
        assert len(cached.findings) == 1

    def test_cache_miss(self, temp_cache):
        """Test cache miss returns None."""
        cached = temp_cache.get("nonexistent.com", ["osint"])
        assert cached is None

    def test_checksum_computation(self):
        """Test checksum computation is consistent."""
        checksum1 = ScanCache._compute_checksum("example.com", ["osint", "web"])
        checksum2 = ScanCache._compute_checksum("example.com", ["web", "osint"])

        # Should be same regardless of module order (sorted)
        assert checksum1 == checksum2

    def test_cache_expiration(self, temp_cache, sample_result):
        """Test cache entries expire correctly."""
        # Create cache with very short TTL
        short_cache = ScanCache(ttl_seconds=1)
        short_cache.cache_dir = temp_cache.cache_dir

        target = "example.com"
        modules = ["osint"]

        short_cache.set(target, modules, sample_result)

        # Should be available immediately
        assert short_cache.get(target, modules) is not None

        # Wait for expiration
        import time
        time.sleep(2)

        # Should be expired
        assert short_cache.get(target, modules) is None

    def test_cache_clear_all(self, temp_cache, sample_result):
        """Test clearing all cache entries."""
        targets = ["example.com", "test.com", "sample.com"]
        modules = ["osint"]

        for target in targets:
            temp_cache.set(target, modules, sample_result)

        assert temp_cache.get_stats()["total_entries"] == 3

        cleared = temp_cache.clear()
        assert cleared == 3
        assert temp_cache.get_stats()["total_entries"] == 0

    def test_cache_clear_specific_target(self, temp_cache, sample_result):
        """Test clearing specific target from cache."""
        targets = ["example.com", "test.com"]
        modules = ["osint"]

        for target in targets:
            temp_cache.set(target, modules, sample_result)

        cleared = temp_cache.clear(target="example.com")
        assert cleared >= 1
        assert temp_cache.get("example.com", modules) is None
        assert temp_cache.get("test.com", modules) is not None

    def test_cache_stats(self, temp_cache, sample_result):
        """Test cache statistics."""
        temp_cache.set("example.com", ["osint"], sample_result)
        temp_cache.set("test.com", ["web"], sample_result)

        stats = temp_cache.get_stats()
        assert stats["total_entries"] == 2
        assert stats["ttl_seconds"] == 3600


class TestCacheEntry:
    """Tests for CacheEntry."""

    def test_cache_entry_expiration(self):
        """Test cache entry expiration check."""
        now = datetime.now(timezone.utc)

        # Not expired
        entry = CacheEntry(
            target="example.com",
            modules=["osint"],
            result_data={},
            created_at=now,
            expires_at=now + timedelta(hours=1),
            checksum="test",
        )
        assert not entry.is_expired()

        # Expired
        entry_expired = CacheEntry(
            target="example.com",
            modules=["osint"],
            result_data={},
            created_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
            checksum="test",
        )
        assert entry_expired.is_expired()

    def test_entry_is_hashable(self):
        """__hash__ returned the checksum string, so hash() raised TypeError."""
        now = datetime.now(timezone.utc)
        entry = CacheEntry(
            target="example.com",
            modules=["osint"],
            result_data={},
            created_at=now,
            expires_at=now + timedelta(hours=1),
            checksum="abc123",
        )

        assert isinstance(hash(entry), int)
        assert hash(entry) == hash("abc123")
        assert len({entry, entry}) == 1
