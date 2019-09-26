"""
Fork of pynxos library from network to code and mzbenami

Reimplemented by ktbyers to support XML-RPC in addition to JSON-RPC
"""
from nxapi_plumbing.device import Device
from nxapi_plumbing.api_client import RPCClient, XMLClient
from nxapi_plumbing.errors import (
    NXAPIError,
    NXAPICommandError,
    NXAPIConnectionError,
    NXAPIAuthError,
    NXAPIPostError,
    NXAPIXMLError,
)

__version__ = "0.6.0"
__all__ = (
    "Device",
    "RPCClient",
    "XMLClient",
    "NXAPIError",
    "NXAPICommandError",
    "NXAPIConnectionError",
    "NXAPIAuthError",
    "NXAPIPostError",
    "NXAPIXMLError",
)
