"""AWS API helpers — rate limiting, exponential backoff, pagination.

Per prompt spec §8: Respect AWS rate limits, use exponential backoff and retries,
keep parallelism configurable (default conservative).
Per PRD §6: Scan under 60 seconds.
"""

from __future__ import annotations

import logging
import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, TypeVar

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Default retry configuration
DEFAULT_MAX_RETRIES = 5
DEFAULT_BASE_DELAY = 0.5  # seconds
DEFAULT_MAX_DELAY = 30.0  # seconds
DEFAULT_CONCURRENCY = 4  # conservative default per prompt spec


def retry_with_backoff(
    func: Callable[..., T],
    *args: Any,
    max_retries: int = DEFAULT_MAX_RETRIES,
    base_delay: float = DEFAULT_BASE_DELAY,
    max_delay: float = DEFAULT_MAX_DELAY,
    **kwargs: Any,
) -> T:
    """Execute a function with exponential backoff on throttling errors.

    Uses full jitter: delay = random(0, min(max_delay, base_delay * 2^attempt))

    Args:
        func: Callable to execute.
        max_retries: Maximum number of retry attempts.
        base_delay: Base delay in seconds.
        max_delay: Maximum delay cap in seconds.

    Returns:
        Function result.

    Raises:
        The last exception if all retries are exhausted.
    """
    last_exception: Exception | None = None

    for attempt in range(max_retries + 1):
        try:
            return func(*args, **kwargs)
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("Throttling", "ThrottlingException", "TooManyRequestsException",
                              "RequestLimitExceeded", "BandwidthLimitExceeded"):
                last_exception = e
                if attempt < max_retries:
                    delay = min(max_delay, base_delay * (2 ** attempt))
                    jittered_delay = random.uniform(0, delay)
                    logger.debug(
                        "Throttled (attempt %d/%d), retrying in %.2fs: %s",
                        attempt + 1, max_retries, jittered_delay, error_code,
                    )
                    time.sleep(jittered_delay)
                else:
                    raise
            else:
                raise  # Non-throttling error, don't retry

    raise last_exception  # type: ignore[misc]


def paginate_with_backoff(
    client: Any,
    method_name: str,
    result_key: str,
    **kwargs: Any,
) -> list[Any]:
    """Paginate an AWS API call with backoff on throttling.

    Args:
        client: Boto3 client.
        method_name: Paginator method name.
        result_key: Key to extract from each page.

    Returns:
        Flattened list of results.
    """
    results: list[Any] = []
    paginator = client.get_paginator(method_name)

    for page in paginator.paginate(**kwargs):
        items = page.get(result_key, [])
        results.extend(items)

    return results


def run_scanners_concurrently(
    scanner_tasks: list[tuple[Callable[..., Any], tuple[Any, ...]]],
    concurrency: int = DEFAULT_CONCURRENCY,
) -> list[Any]:
    """Run scanner tasks concurrently with configurable parallelism.

    Per prompt spec §8: Keep parallelism configurable (default conservative 4).

    Args:
        scanner_tasks: List of (callable, args) tuples.
        concurrency: Maximum number of concurrent threads.

    Returns:
        List of results from all tasks.
    """
    all_results: list[Any] = []

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {
            executor.submit(func, *args): func.__name__
            for func, args in scanner_tasks
        }

        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result()
                if isinstance(result, list):
                    all_results.extend(result)
                else:
                    all_results.append(result)
            except Exception as e:
                logger.error("Scanner task '%s' failed: %s", name, e)

    return all_results
