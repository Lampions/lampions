__all__ = ["__version__"]

from . import console
from ._version import __version__


def main():
    console.run()
