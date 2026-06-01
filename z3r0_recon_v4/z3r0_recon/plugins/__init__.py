"""
plugins/__init__.py — Plugin package auto-registration.

All ReconPlugin subclasses defined in this package are automatically
discovered by PluginRegistry.discover(). No manual import needed
when adding new plugin modules — drop a file in plugins/ and it works.
"""

from . import (
    nmap,
    web,
    services,
    subdomain_enum,
    masscan_scan,
    nuclei_scan,
    httpx_probe,
    arjun_plugin,
    osint_collector,
    cloud_enum,
)

__all__ = [
    "nmap", "web", "services",
    "subdomain_enum", "masscan_scan", "nuclei_scan",
    "httpx_probe", "arjun_plugin", "osint_collector", "cloud_enum",
]
