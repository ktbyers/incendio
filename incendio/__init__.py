import pkg_resources
import sys
from incendio.base import get_network_driver
from incendio._SUPPORTED_DRIVERS import SUPPORTED_DRIVERS

# Verify Python Version that is running
try:
    if not (sys.version_info.major == 3 and sys.version_info.minor >= 6):
        raise RuntimeError("Incendio requires Python 3.6 or greater")
except AttributeError:
    raise RuntimeError("Incendio requires Python 3.6 or greater")

try:
    __version__ = pkg_resources.get_distribution("incendio").version
except pkg_resources.DistributionNotFound:
    __version__ = "Not installed"

__all__ = ("get_network_driver", "SUPPORTED_DRIVERS")
