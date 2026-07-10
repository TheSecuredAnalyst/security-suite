"""SQL Injection vulnerability scanner."""

import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from core import load_wordlist
from core.http_client import HTTPClient
from core.models import ScanResult, Severity, Target
from modules.webscanner.base import WebScannerModule


class SQLiScanner(WebScannerModule):
    """Scan for SQL Injection vulnerabilities."""

    name = "sqli"
    description = "Test for SQL injection vulnerabilities"

    SECLISTS_RELATIVE_PATHS = (
        "Fuzzing/Databases/SQLi/quick-SQLi.txt",
        "Fuzzing/Databases/SQLi/Generic-SQLi.txt",
    )

    # Built-in fallback error-based detection payloads
    PAYLOADS = [
        "'",
        "''",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
        "1 AND 1=1",
        "1 AND 1=2",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "-1 OR 1=1",
        "1; SELECT 1--",
        "1' UNION SELECT NULL--",
        "admin'--",
    ]

    # SQL error patterns
    ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySqlException",
        r"valid MySQL result",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_",
        r"valid PostgreSQL result",
        r"Driver.*SQL[\-\_\ ]*Server",
        r"OLE DB.*SQL Server",
        r"SQLServer JDBC Driver",
        r"Microsoft SQL Native Client error",
        r"\[SQL Server\]",
        r"ODBC SQL Server Driver",
        r"SQLSrv",
        r"Oracle.*Driver",
        r"Warning.*oci_",
        r"Warning.*ora_",
        r"ORA-\d{5}",
        r"Oracle error",
        r"SQLite\/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"sqlite3\.OperationalError",
        r"org\.sqlite\.JDBC",
        r"Unclosed quotation mark",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
        r"unexpected end of SQL command",
        r"SQLSTATE\[",
        r"syntax error at or near",
    ]

    def __init__(
        self,
        custom_payloads: list[str] | None = None,
        seclists_path: str | None = None,
    ):
        super().__init__()
        self.payloads = custom_payloads or load_wordlist(
            self.SECLISTS_RELATIVE_PATHS,
            fallback=self.PAYLOADS,
            seclists_path=seclists_path,
        )
        self.error_patterns = [re.compile(p, re.IGNORECASE) for p in self.ERROR_PATTERNS]

    async def run(self, target: Target) -> ScanResult:
        """Scan target for SQL injection vulnerabilities."""
        result = self.create_result(target)

        url = self._build_url(target)
        self.logger.info(f"Starting SQLi scan on {url}")

        vulnerabilities = []

        try:
            async with HTTPClient() as client:
                # Get baseline response
                baseline = await client.get(url)
                baseline_length = len(baseline.text)

                parsed = urlparse(str(baseline.url))
                params = parse_qs(parsed.query)

                if not params:
                    params = {"id": ["1"], "user": ["1"], "page": ["1"]}

                for param_name in params.keys():
                    for payload in self.payloads:
                        test_url = self._inject_payload(url, param_name, payload)

                        try:
                            test_response = await client.get(test_url)

                            # Check for SQL errors
                            error_found = self._check_sql_errors(test_response.text)
                            if error_found:
                                vuln = {
                                    "type": "Error-based SQLi",
                                    "url": test_url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "error": error_found,
                                }
                                vulnerabilities.append(vuln)
                                self.logger.warning(f"SQL error detected: {param_name}")
                                break

                            # Boolean-based detection
                            length_diff = abs(len(test_response.text) - baseline_length)
                            if length_diff > 100 and "1=1" in payload:
                                # Try false condition
                                false_url = self._inject_payload(url, param_name, payload.replace("1=1", "1=2"))
                                false_response = await client.get(false_url)

                                if abs(len(test_response.text) - len(false_response.text)) > 100:
                                    vuln = {
                                        "type": "Boolean-based SQLi",
                                        "url": test_url,
                                        "parameter": param_name,
                                        "payload": payload,
                                        "evidence": f"Response length varies: true={len(test_response.text)}, false={len(false_response.text)}",
                                    }
                                    vulnerabilities.append(vuln)
                                    self.logger.warning(f"Boolean SQLi detected: {param_name}")
                                    break

                        except Exception as e:
                            self.logger.debug(f"Error testing payload: {e}")

            result.raw_data["tested_parameters"] = list(params.keys())
            result.raw_data["vulnerabilities"] = vulnerabilities

            if vulnerabilities:
                result.add_finding(
                    title="SQL Injection Vulnerabilities Detected",
                    description=f"Found {len(vulnerabilities)} potential SQLi vulnerability/vulnerabilities",
                    severity=Severity.CRITICAL,
                    data={"vulnerabilities": vulnerabilities},
                    references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                )
            else:
                result.add_finding(
                    title="No SQL Injection Found",
                    description=f"Tested {len(params)} parameter(s) with {len(self.payloads)} payload(s)",
                    severity=Severity.INFO,
                )

        except Exception as e:
            result.errors.append(f"SQLi scan failed: {str(e)}")
            result.success = False

        result.complete()
        return result

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]

        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

    def _check_sql_errors(self, html: str) -> str | None:
        """Check for SQL error messages."""
        for pattern in self.error_patterns:
            match = pattern.search(html)
            if match:
                return match.group(0)
        return None

    def _build_url(self, target: Target) -> str:
        if target.target_type == "url":
            return target.value
        return f"https://{target.value}"
