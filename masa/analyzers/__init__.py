"""Rule plugins. Importing this package registers every analyzer."""

from masa.analyzers.base import Analyzer, all_analyzers, register, registry_names

# Import order defines the order findings are produced in.
from masa.analyzers import (  # noqa: F401  (imported for the side effect of registering)
    archive,
    secrets,
    manifest,
    storage,
    network,
    crypto,
    webview,
    privacy,
    binary,
    dependencies,
    ios_config,
)

__all__ = ["Analyzer", "all_analyzers", "register", "registry_names"]
