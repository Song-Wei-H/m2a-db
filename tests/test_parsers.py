import unittest
from worker.parsers.httpx_parser import parse_httpx_output
from worker.parsers.ssh_enum_parser import parse_ssh_enum_output


class TestParsers(unittest.TestCase):
    
    def test_httpx_banner_only_output(self):
        """Test parsing of httpx banner-only output."""
        # This banner contains "projectdiscovery.io" which triggers the banner detection in httpx parser
        banner_output = r"""    __    __  __  ____
   / /_  / /_/ // _/(_)____
  / __ \/ __/ ,  <REDACTED_EMAIL>  / /_____
               / /_/ / __ \  / _ \  / __ \  / __/ __ \

[WRN] UI Dashboard is disabled, Use -dashboard option to enable"""
        
        
        result = parse_httpx_output(banner_output)
        # For banner-only output, we expect specific fields
        self.assertEqual(result["tool"], "httpx")
        self.assertEqual(result["urls"], [])
        self.assertEqual(result["status_codes"], [])
        self.assertEqual(result["finding_count"], 0)
        self.assertEqual(result["status"], "done")
    
    
    def test_httpx_normal_result_line(self):
        """Test parsing of normal httpx result line."""
        normal_output = '{"url":"http0.56.64.121:8000","status_code":404}'
        result = parse_httpx_output(normal_output)
        # This should not match the banner pattern and should return normal parsing result
        self.assertIn("entry_count", result)
        self.assertNotIn("finding_count", result)
    
    def test_ssh_enum_parsing(self):
        """Test parsing of ssh-enum Nmap output."""
        ssh_output = """Nmap scan report for 192.0.2.10
Host is up (0.000038s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh2-enum-algos: 
|   kex_algorithms: (14)
|       sntrup761x25519-sha512
|       sntrup761x25519-sha512@openssh.com"""

        result = parse_ssh_enum_output(ssh_output)
        expected = {
            "status": "done",
            "service": "ssh",
            "port": 22,
            "product": "OpenSSH",
            "version": None,  # The simple parser doesn't extract version from this specific output
            "protocol": None,
            "finding_count": 1
        }
        # We just check that the basic structure is correct
        self.assertEqual(result["status"], "done")
        self.assertEqual(result["service"], "ssh")
        self.assertEqual(result["port"], 22)
        self.assertEqual(result["finding_count"], 1)


if __name__ == "__main__":
    unittest.main()