"""
Bloodhound Nmap Scanner

Transform Nmap scan results into BloodHound-compatible OpenGraph format for network analysis.
"""

__version__ = "0.2.0"
__author__ = "rreichel3"

from .main import main, scan_hosts, convert_nmap_to_servers

__all__ = ["main", "scan_hosts", "convert_nmap_to_servers"]