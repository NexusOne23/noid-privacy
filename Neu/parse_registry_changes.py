#!/usr/bin/env python3
"""
Registry Changes Parser
=======================
Parst registry-changes-complete.txt und erstellt eine PowerShell-Definition
für das spezifische Backup/Restore System.

Usage:
    python3 parse_registry_changes.py registry-changes-complete.txt > RegistryChanges-Definition.ps1
"""

import re
import sys
from typing import List, Dict, Optional

class RegistryEntry:
    def __init__(self):
        self.line_number: Optional[int] = None
        self.path: Optional[str] = None
        self.name: Optional[str] = None
        self.value: Optional[str] = None
        self.type: Optional[str] = None
        self.description: Optional[str] = None
        self.file: Optional[str] = None
        
    def is_complete(self) -> bool:
        """Check if all required fields are present"""
        return all([self.path, self.name, self.type is not None])
    
    def to_powershell(self) -> str:
        """Convert to PowerShell hashtable"""
        # Escape quotes in strings
        path_escaped = self.path.replace("'", "''")
        name_escaped = self.name.replace("'", "''")
        desc_escaped = self.description.replace("'", "''") if self.description else ""
        
        # Convert value to proper PowerShell format
        if self.type == "DWord":
            value_str = str(self.value)
        elif self.type == "String":
            # String values need quotes
            value_escaped = str(self.value).replace("'", "''")
            value_str = f"'{value_escaped}'"
        else:
            value_str = str(self.value)
        
        return (
            f"    @{{\n"
            f"        Path = '{path_escaped}'\n"
            f"        Name = '{name_escaped}'\n"
            f"        Type = '{self.type}'\n"
            f"        ApplyValue = {value_str}\n"
            f"        Description = '{desc_escaped}'\n"
            f"        File = '{self.file}'\n"
            f"    }}"
        )

def parse_registry_changes(file_path: str) -> List[RegistryEntry]:
    """Parse the registry changes text file"""
    entries = []
    current_entry = None
    current_file = None
    
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.rstrip()
            
            # Detect file section
            if line.startswith("DATEI: "):
                current_file = line.replace("DATEI: ", "").strip()
                continue
            
            # Detect new entry
            match = re.match(r'^\[(\d+)\] Zeile \d+:', line)
            if match:
                # Save previous entry
                if current_entry and current_entry.is_complete():
                    entries.append(current_entry)
                
                # Start new entry
                current_entry = RegistryEntry()
                current_entry.file = current_file
                continue
            
            if current_entry is None:
                continue
            
            # Parse fields
            if line.startswith("    Registry-Pfad: "):
                current_entry.path = line.replace("    Registry-Pfad: ", "").strip()
            elif line.startswith("    Name:          "):
                current_entry.name = line.replace("    Name:          ", "").strip()
            elif line.startswith("    Wert:          "):
                value_str = line.replace("    Wert:          ", "").strip()
                # Remove quotes from string values
                if value_str.startswith('"') and value_str.endswith('"'):
                    current_entry.value = value_str[1:-1]
                else:
                    current_entry.value = value_str
            elif line.startswith("    Typ:           "):
                current_entry.type = line.replace("    Typ:           ", "").strip()
            elif line.startswith("    Beschreibung:  "):
                current_entry.description = line.replace("    Beschreibung:  ", "").strip()
        
        # Don't forget last entry
        if current_entry and current_entry.is_complete():
            entries.append(current_entry)
    
    return entries

def generate_powershell_definition(entries: List[RegistryEntry]) -> str:
    """Generate PowerShell definition file"""
    
    header = """<#
.SYNOPSIS
    Registry Changes Definition
    
.DESCRIPTION
    Contains all 375 registry changes that the Security Baseline applies.
    Used by Backup and Restore scripts for specific (fast) backup/restore.
    
    This file was AUTO-GENERATED from registry-changes-complete.txt
    Do not modify manually - regenerate from source!
    
.NOTES
    Generated: {date}
    Total Entries: {count}
    Source: registry-changes-complete.txt
#>

# Registry changes that Security Baseline applies
$script:RegistryChanges = @(
"""
    
    footer = """
)

# Export for use in other scripts
Export-ModuleMember -Variable RegistryChanges
"""
    
    # Generate entries
    from datetime import datetime
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    result = header.format(date=now, count=len(entries))
    
    # Add entries
    for i, entry in enumerate(entries):
        result += entry.to_powershell()
        if i < len(entries) - 1:
            result += ",\n"
        else:
            result += "\n"
    
    result += footer
    
    return result

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 parse_registry_changes.py registry-changes-complete.txt", file=sys.stderr)
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    try:
        # Parse
        entries = parse_registry_changes(input_file)
        
        # Filter out incomplete entries (e.g. Set-ItemProperty without proper data)
        valid_entries = [e for e in entries if e.is_complete() and e.path and e.name]
        
        print(f"# Parsed {len(entries)} entries, {len(valid_entries)} valid", file=sys.stderr)
        
        # Generate PowerShell
        powershell_code = generate_powershell_definition(valid_entries)
        
        # Output
        print(powershell_code)
        
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
