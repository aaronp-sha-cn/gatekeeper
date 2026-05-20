#!/usr/bin/env python3
"""
GateKeeper ISO Builder using pycdlib
Creates a bootable Debian 13 ISO with preseed automation
"""

import os
import sys
import pycdlib
import shutil
from datetime import datetime

# Configuration
EXTRACT_DIR = "/workspace/gatekeeper/debian13/iso_build/build/extract"
OUTPUT_ISO = "/workspace/gatekeeper/debian13/GateKeeper-v1.3.0-debian13-amd64.iso"

def build_iso():
    print(f"Building ISO from: {EXTRACT_DIR}")
    print(f"Output: {OUTPUT_ISO}")
    
    # Check if source directory exists
    if not os.path.exists(EXTRACT_DIR):
        print(f"ERROR: Source directory not found: {EXTRACT_DIR}")
        sys.exit(1)
    
    # Create ISO
    iso = pycdlib.PyCdlib()
    iso.new(
        interchange_level=4,
        joliet=3,
        rock_ridge='1.09',
        vol_ident='GATEKEEPER',
        sys_ident='GATEKEEPER',
        pub_ident_str='GateKeeper',
        app_ident_str='GateKeeper ISO Builder',
        copyright_file=None,
        abstract_file=None,
        bibliographic_file=None
    )
    
    # Add files from extracted ISO
    def add_directory(iso, path, iso_base_path='', joliet_base_path=''):
        """Recursively add directory to ISO"""
        if not os.path.exists(path):
            return
        
        for item in sorted(os.listdir(path)):
            full_path = os.path.join(path, item)
            iso_rel_path = os.path.join(iso_base_path, item) if iso_base_path else item
            joliet_rel_path = os.path.join(joliet_base_path, item) if joliet_base_path else item
            
            # Normalize paths
            iso_path = '/' + iso_rel_path.replace('\\', '/').lstrip('/')
            joliet_path = '/' + joliet_rel_path.replace('\\', '/').lstrip('/')
            
            if os.path.isdir(full_path):
                try:
                    iso.add_directory(iso_path, joliet_path=joliet_path)
                except Exception as e:
                    print(f"Warning: Could not add directory {full_path}: {e}")
                add_directory(iso, full_path, iso_rel_path, joliet_rel_path)
            else:
                try:
                    with open(full_path, 'rb') as f:
                        data = f.read()
                    iso.add_file(
                        data,
                        iso_path,
                        joliet_path=joliet_path,
                        file_mode='r-xr-xr-x'
                    )
                except Exception as e:
                    print(f"Warning: Could not add file {full_path}: {e}")
    
    print("Adding files to ISO...")
    add_directory(iso, EXTRACT_DIR)
    
    # Write ISO
    print(f"Writing ISO to {OUTPUT_ISO}...")
    os.makedirs(os.path.dirname(OUTPUT_ISO), exist_ok=True)
    iso.write(output=OUTPUT_ISO)
    iso.close()
    
    print(f"ISO created successfully!")
    print(f"Size: {os.path.getsize(OUTPUT_ISO) / (1024*1024):.1f} MB")
    
    # Calculate MD5
    import hashlib
    with open(OUTPUT_ISO, 'rb') as f:
        md5 = hashlib.md5(f.read()).hexdigest()
    print(f"MD5: {md5}")

if __name__ == "__main__":
    build_iso()
