import re
from typing import Any


def parse_ssh_enum_output(raw_output: str) -> dict[str, Any]:
    """
    Parse Nmap SSH enumeration output.
    
    Expected format:
    {
      "status": "done",
      "service": "ssh",
      "port": 22,
      "product": "OpenSSH",
      "version": "9.9p1 Debian 3",
      "protocol": "2.0",
      "finding_count": 1
    }
    """
    # Initialize default values
    result = {
        "status": "done",
        "service": "ssh",
        "port": None,
        "product": None,
        "version": None,
        "protocol": None,
        "finding_count": 0
    }
    
    # Parse the Nmap output to extract SSH information
    lines = raw_output.splitlines()
    
    # Look for the service line to get port and service info
    for line in lines:
        if "22/tcp open" in line and "ssh" in line:
            result["port"] = 22
            result["finding_count"] = 1
            break
    
    # Look for version information in the output
    # This is a simplified parser that looks for common SSH version patterns
    for line in lines:
        if "ssh" in line.lower():
            # Extract version from lines that might contain it
            if "openssh" in line.lower() or "ssh-" in line.lower():
                # Try to extract version information
                # This is a simple pattern matching approach
                if "openssh" in line.lower():
                    result["product"] = "OpenSSH"
                    # Try to find version in the line
                    match = re.search(r'OpenSSH[^\n]*', line, re.IGNORECASE)
                    if match:
                        version_text = match.group(0)
                        # Extract version number
                        version_match = re.search(r'(\d+\.\d+)', version_text)
                        if version_match:
                            result["version"] = version_match.group(1)
    
    return result