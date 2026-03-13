"""Scanner registry for CloudGuard.

Maintains a mapping of service names to scanner classes.
Scanners self-register via the @register_scanner decorator.
"""

from __future__ import annotations

from typing import Type

from cloudguard.scanners.base import BaseScanner

_REGISTRY: dict[str, Type[BaseScanner]] = {}


def register_scanner(cls: Type[BaseScanner]) -> Type[BaseScanner]:
    """Decorator to register a scanner class in the global registry.

    Usage:
        @register_scanner
        class S3Scanner(BaseScanner):
            service_name = "s3"
    """
    if not cls.service_name:
        raise ValueError(f"Scanner {cls.__name__} must define service_name")
    _REGISTRY[cls.service_name] = cls
    return cls


def get_scanner(service: str) -> BaseScanner:
    """Get an instance of a scanner by service name.

    Args:
        service: AWS service name (e.g., 's3', 'iam').

    Returns:
        Scanner instance.

    Raises:
        KeyError: If no scanner registered for the service.
    """
    if service not in _REGISTRY:
        raise KeyError(
            f"No scanner registered for service '{service}'. "
            f"Available: {list(_REGISTRY.keys())}"
        )
    return _REGISTRY[service]()


def get_all_scanners() -> dict[str, BaseScanner]:
    """Get instances of all registered scanners.

    Returns:
        Dictionary mapping service name to scanner instance.
    """
    return {name: cls() for name, cls in _REGISTRY.items()}


def list_services() -> list[str]:
    """List all registered service names.

    Returns:
        Sorted list of service names.
    """
    return sorted(_REGISTRY.keys())
