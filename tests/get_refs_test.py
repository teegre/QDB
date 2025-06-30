import os
import pytest
import sys
import time


sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.storage import Store

@pytest.fixture
def store():
  qdb = Store('persons.qdb')
  return qdb

def test_direct_ref(store):
    """Direct relationship test: person -> country"""
    person_key = "person:00001"
    results = store.get_refs(person_key, "country")
    assert results == ["country:08"], f"Expected only 'country:08' for person:00001, got {results}"

def test_reverse_ref(store):
    """Reverse relationship test: country -> person"""
    country_key = "country:08"
    results = store.get_refs(country_key, "person")
    assert "person:00001" in results, "Expected person:00001 in results for country:08"

def test_indirect_ref(store):
    """Indirect multi-hop test: person -> city (via address)"""
    person_key = "person:00001"
    results = store.get_refs(person_key, "city")
    assert results, "Expected person -> city results to be non-empty"

    # Check results are only instances of city
    assert all(r.startswith("city:") for r in results)

def test_no_path(store):
    """Test when no path exists between indexes"""
    results = store.get_refs("person:00001", "unrelated_index")
    assert results == [], "Expected no results for unrelated indexes"

def test_cache(store):
    """Test that get_refs is cached for subsequent calls."""
    key = "country:01"
    index = "person"

    # First call: measure duration
    t0 = time.perf_counter()
    results_first = store.get_refs(key, index)
    first_duration = time.perf_counter() - t0
    assert results_first, "Expected results for first call"

    # Second call: measure duration
    t1 = time.perf_counter()
    results_second = store.get_refs(key, index)
    second_duration = time.perf_counter() - t1
    assert results_second == results_first, "Results should be identical"

    # Check that second call is significantly faster
    assert second_duration < first_duration / 10, (
        f"Expected second call to be much faster (first={first_duration:.5f}s, second={second_duration:.5f}s)"
    )


def test_multiple_hop(store):
    """Test multi-hop path person -> address -> city -> country"""
    person_key = "person:00001"
    results = store.get_refs(person_key, "country")
    assert results == ["country:08"], "Expected person -> country path to be resolved correctly"

def test_get_refs_with_index(store):
    """Test direct reference retrieval"""
    person_key = "person:00001"
    results = store.get_refs_with_index(person_key, "country")
    assert results == set(), "Expected no direct ref with index"

