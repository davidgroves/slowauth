#!/usr/bin/env python3
"""Test script to verify random delay feature."""

import subprocess
import time
import statistics

def test_random_delays(domain: str, low: int, high: int, count: int = 20):
    """Test random delays and verify they're within range."""
    print(f"\nTesting random-{low}-{high}.{domain} with {count} queries...")
    
    delays = []
    for i in range(count):
        start = time.time()
        result = subprocess.run(
            ["dig", "@127.0.0.1", "-p", "55533", f"random-{low}-{high}.{domain}", "TXT", "+short"],
            capture_output=True,
            text=True
        )
        elapsed = (time.time() - start) * 1000  # Convert to milliseconds
        
        if result.returncode == 0:
            delays.append(elapsed)
            print(f"  Query {i+1}: {elapsed:.1f}ms")
        else:
            print(f"  Query {i+1}: FAILED")
    
    if delays:
        print(f"\nResults:")
        print(f"  Count: {len(delays)}")
        print(f"  Min: {min(delays):.1f}ms")
        print(f"  Max: {max(delays):.1f}ms")
        print(f"  Mean: {statistics.mean(delays):.1f}ms")
        print(f"  Median: {statistics.median(delays):.1f}ms")
        print(f"  Expected range: {low}-{high}ms")
        
        # Check if all delays are within range (with some tolerance for network overhead)
        tolerance = 50  # 50ms tolerance for network overhead
        all_in_range = all(low - tolerance <= d <= high + tolerance for d in delays)
        
        if all_in_range:
            print(f"  ✓ All delays within expected range (with {tolerance}ms tolerance)")
        else:
            out_of_range = [d for d in delays if not (low - tolerance <= d <= high + tolerance)]
            print(f"  ✗ {len(out_of_range)} delays out of range: {out_of_range}")
        
        return all_in_range
    return False

if __name__ == "__main__":
    domain = "example.com"
    
    print("=" * 60)
    print("Testing SlowAuth Random Delay Feature")
    print("=" * 60)
    
    # Test 1: Narrow range
    test_random_delays(domain, 100, 200, count=10)
    
    # Test 2: Wider range
    test_random_delays(domain, 50, 500, count=10)
    
    # Test 3: Small range
    test_random_delays(domain, 200, 250, count=10)
    
    print("\n" + "=" * 60)
    print("Tests completed!")
    print("=" * 60)
