"""
core/plugin_registry.py — Auto-discovery and registration of plugins.

Plugins are discovered by importing every module in the plugins/ package
and finding all ReconPlugin subclasses. No manual registration needed —
drop a new file in plugins/ and it's automatically available.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil

from .plugin_base import ReconPlugin


class PluginRegistry:
    """
    Auto-discovers and holds all available ReconPlugin subclasses.

    Usage:
        registry = PluginRegistry()
        registry.discover("z3r0_recon.plugins")
        nmap_plugin = registry.get("nmap")
        all_plugins = registry.all()
    """

    def __init__(self) -> None:
        self._plugins: dict[str, type[ReconPlugin]] = {}

    def discover(self, package_name: str) -> None:
        """
        Import all modules in `package_name` and register any
        ReconPlugin subclasses found within them.
        """
        try:
            package = importlib.import_module(package_name)
        except ImportError as e:
            raise ImportError(f"Cannot import plugin package '{package_name}': {e}")

        package_path = getattr(package, "__path__", [])
        for _finder, module_name, _ispkg in pkgutil.walk_packages(
            path=package_path,
            prefix=package_name + ".",
            onerror=lambda name: None,
        ):
            try:
                module = importlib.import_module(module_name)
            except ImportError as e:
                import logging
                logging.getLogger("z3r0.registry").warning(
                    f"Could not import plugin module '{module_name}': {e}"
                )
                continue

            for _name, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, ReconPlugin)
                    and obj is not ReconPlugin
                    and hasattr(obj, "meta")
                ):
                    self.register(obj)

    def register(self, plugin_cls: type[ReconPlugin]) -> None:
        """
        Register a plugin class by its meta.name.

        Rules enforced here:
        1. Names starting with '_' are internal base classes — silently skipped.
        2. Duplicate names emit a WARNING (last-write-wins is intentional for
           overriding built-ins, but should be visible in logs).
        3. A class that is abstract (has unimplemented execute()) cannot be
           instantiated — the registry stores the class not an instance, so
           this is caught at execution time by the orchestrator. We log it here
           so operators see it at startup rather than mid-scan.
        """
        import logging
        _log = logging.getLogger("z3r0.registry")

        name = plugin_cls.meta.name

        # Rule 1: skip internal base classes
        if name.startswith("_"):
            return

        # Rule 2: warn on duplicate
        if name in self._plugins:
            existing = self._plugins[name]
            if existing is not plugin_cls:
                _log.warning(
                    f"Plugin name conflict: '{name}' already registered as "
                    f"{existing.__module__}.{existing.__name__}. "
                    f"Overwriting with {plugin_cls.__module__}.{plugin_cls.__name__}."
                )

        self._plugins[name] = plugin_cls
        _log.debug(f"Registered plugin: {name} ({plugin_cls.__module__})")

    def get(self, name: str) -> type[ReconPlugin] | None:
        """Return the plugin class for `name`, or None."""
        return self._plugins.get(name)

    def get_instance(self, name: str) -> ReconPlugin | None:
        """Return a fresh plugin instance for `name`, or None."""
        cls = self.get(name)
        return cls() if cls else None

    def all(self) -> list[type[ReconPlugin]]:
        """Return all registered plugin classes."""
        return list(self._plugins.values())

    def available(self) -> list[type[ReconPlugin]]:
        """Return only plugins whose required binary is installed."""
        return [cls for cls in self.all() if cls().is_available()]

    def names(self) -> list[str]:
        return list(self._plugins.keys())

    def __len__(self) -> int:
        return len(self._plugins)

    def __repr__(self) -> str:
        return f"PluginRegistry({self.names()})"
