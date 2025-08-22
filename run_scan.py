#!/usr/bin/env python3
"""
Convenience script to run bloodhound-nmap scans.
Usage: python run_scan.py scan_config.json
"""

import sys
from bloodhound_nmap.main import main

if __name__ == "__main__":
    main()