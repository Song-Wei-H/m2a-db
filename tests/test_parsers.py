import unittest

from worker.parsers.dirb_parser import parse_dirb_output
from worker.parsers.httpx_parser import parse_httpx_output
from worker.parsers.mysql_info_parser import parse_mysql_info_output
from worker.parsers.nmap_parser import parse_nmap_output, parse_nmap_result
from worker.parsers.nuclei_parser import parse_nuclei_output
from worker.parsers.ssh_enum_parser import parse_ssh_enum_output
from worker.parsers.tool_result_parser import parse_tool_output


REQUIRED_KEYS = {
    "tool_name",
    "success",
    "evidence_type",
    "service",
    "port",
    "url",
    "host",
    "findings",
    "raw_summary",
}


class TestParsers(unittest.TestCase):
    def assert_stable_result(self, result):
        self.assertTrue(REQUIRED_KEYS.issubset(result.keys()))
        self.assertIsInstance(result["findings"], list)
        self.assertIn("finding_count", result)

    def test_httpx_banner_only_output(self):
        banner_output = r"""    __    __  __  ____
   / /_  / /_/ // _/(_)____
  / __ \/ __/ ,  <REDACTED_EMAIL>  / /_____
               / /_/ / __ \  / _ \  / __ \  / __/ __ \

[WRN] UI Dashboard is disabled, Use -dashboard option to enable"""

        result = parse_httpx_output(banner_output)
        self.assert_stable_result(result)
        self.assertEqual(result["tool"], "httpx")
        self.assertEqual(result["urls"], [])
        self.assertEqual(result["status_codes"], [])
        self.assertEqual(result["finding_count"], 0)
        self.assertEqual(result["status"], "done")

    def test_httpx_normal_result_line(self):
        normal_output = '{"url":"http://192.0.2.10:8000","status_code":404,"title":"Not Found"}'
        result = parse_httpx_output(normal_output)
        self.assert_stable_result(result)
        self.assertEqual(result["entry_count"], 1)
        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(result["url"], "http://192.0.2.10:8000")
        self.assertEqual(result["port"], None)

    def test_nmap_list_parser_is_backward_compatible(self):
        output = "22/tcp open ssh OpenSSH 9.6\n443/tcp open https nginx 1.25"
        result = parse_nmap_output(output)
        self.assertEqual(result[0]["port"], 22)
        self.assertEqual(result[1]["service"], "https")

    def test_nmap_result_parser_returns_stable_dict(self):
        output = "22/tcp open ssh OpenSSH 9.6\n443/tcp open https nginx 1.25"
        result = parse_nmap_result(output, host="example.com")
        self.assert_stable_result(result)
        self.assertEqual(result["tool_name"], "nmap_service")
        self.assertEqual(result["evidence_type"], "open_ports")
        self.assertEqual(result["finding_count"], 2)
        self.assertEqual(result["host"], "example.com")

    def test_nuclei_jsonl_parser(self):
        output = (
            '{"template-id":"tech-detect","info":{"name":"Tech Detect","severity":"info"},'
            '"matched-at":"https://example.com","type":"http"}'
        )
        result = parse_nuclei_output(output, host="example.com", port=443)
        self.assert_stable_result(result)
        self.assertEqual(result["tool_name"], "nuclei_safe")
        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(result["findings"][0]["template_id"], "tech-detect")

    def test_dirb_parser(self):
        output = "+ http://example.com/admin (CODE:200|SIZE:1234)\n==> DIRECTORY: http://example.com/assets/"
        result = parse_dirb_output(output)
        self.assert_stable_result(result)
        self.assertEqual(result["tool_name"], "dirb_safe")
        self.assertEqual(result["finding_count"], 2)
        self.assertIn("/admin", result["found_paths"])

    def test_ssh_enum_parsing(self):
        ssh_output = """Nmap scan report for 192.0.2.10
Host is up (0.000038s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh2-enum-algos:
|   kex_algorithms: (14)
|       sntrup761x25519-sha512
|       sntrup761x25519-sha512@openssh.com"""

        result = parse_ssh_enum_output(ssh_output)
        self.assert_stable_result(result)
        self.assertEqual(result["status"], "done")
        self.assertEqual(result["service"], "ssh")
        self.assertEqual(result["port"], 22)
        self.assertEqual(result["finding_count"], 1)

    def test_mysql_info_parser(self):
        output = "Protocol: 10\nVersion: 8.0.35 MySQL Community Server\nAccess denied for user"
        result = parse_mysql_info_output(output, host="db.example.com")
        self.assert_stable_result(result)
        self.assertEqual(result["tool_name"], "mysql-info")
        self.assertEqual(result["service"], "mysql")
        self.assertEqual(result["port"], 3306)
        self.assertEqual(result["finding_count"], 1)

    def test_all_parsers_handle_empty_and_failed_output(self):
        for tool_name in (
            "nmap_service",
            "httpx_basic",
            "nuclei_safe",
            "dirb_safe",
            "ssh-enum",
            "mysql-info",
        ):
            result = parse_tool_output(tool_name, "", success=False, host="example.com")
            self.assert_stable_result(result)
            self.assertFalse(result["success"])
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["raw_summary"], "")


if __name__ == "__main__":
    unittest.main()
