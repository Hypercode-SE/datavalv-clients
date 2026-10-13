"""Datavalv's Python client: the file format, the crypto, and the four calls.

`crypto` and `format` are the primitives, checked against the TypeScript
implementation by the conformance matrix. `client.DatavalvClient` is the HTTP
layer over them, and `cli` is the `datavalv` command an operator runs.
"""

from .client import CreatedVault, DatavalvClient, PushedBackup
from .errors import (
    ApiError,
    AuthError,
    ConfigurationError,
    DatavalvError,
    NetworkError,
    QuotaExceeded,
    RequestInFlight,
    StorageFull,
    UploadError,
    VaultKeyChanged,
    VaultNotInitialized,
)
from .pins import FilePins, KeyPins, MemoryPins

__version__ = "0.7.0"

__all__ = [
    "ApiError",
    "AuthError",
    "ConfigurationError",
    "CreatedVault",
    "DatavalvClient",
    "DatavalvError",
    "FilePins",
    "KeyPins",
    "MemoryPins",
    "NetworkError",
    "PushedBackup",
    "QuotaExceeded",
    "RequestInFlight",
    "StorageFull",
    "UploadError",
    "VaultKeyChanged",
    "VaultNotInitialized",
    "__version__",
]
