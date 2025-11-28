"""
Security Scanner Module
Automated security scanning for MCP servers
"""

import logging
import json
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path

from mcp_security.client.mcp_client import MCPClient
from mcp_security.attacks.prompt_injection_impl import PromptInjector, InjectionType
from mcp_security.attacks.pentest import PenetrationTester, VulnerabilityType

logger = logging.getLogger(__name__)


class SecurityScanner:
    """
    Automated security scanner that runs comprehensive tests on MCP servers
    """

    def __init__(
        self,
        base_url: str,
        timeout: int = 30,
        verify_ssl: bool = True,
    ):
        """
        Initialize security scanner
        
        Args:
            base_url: Base URL of the MCP server
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = base_url
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.client: Optional[MCPClient] = None
        self.prompt_injector: Optional[PromptInjector] = None
        self.pentest: Optional[PenetrationTester] = None

    async def initialize(self):
        """Initialize scanner components"""
        self.client = MCPClient(
            base_url=self.base_url,
            timeout=self.timeout,
            verify_ssl=self.verify_ssl,
        )
        await self.client.connect()
        
        self.prompt_injector = PromptInjector(self.client)
        self.pentest = PenetrationTester(self.client)
        
        logger.info(f"Scanner initialized for {self.base_url}")

    async def cleanup(self):
        """Cleanup scanner resources"""
        if self.client:
            await self.client.close()

    async def run_full_scan(
        self,
        include_prompt_injection: bool = True,
        include_pentest: bool = True,
    ) -> Dict[str, Any]:
        """
        Run a full security scan
        
        Args:
            include_prompt_injection: Whether to include prompt injection tests
            include_pentest: Whether to include penetration tests
            
        Returns:
            Dictionary containing full scan results
        """
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        logger.info(f"Starting full security scan (ID: {scan_id})")
        
        results = {
            "scan_id": scan_id,
            "target": self.base_url,
            "timestamp": datetime.now().isoformat(),
            "tests_run": [],
            "summary": {},
        }

        # Discover available tools
        logger.info("Discovering available tools...")
        tools_response = await self.client.list_tools()
        tools = []
        
        if tools_response.success and tools_response.data:
            tools = tools_response.data.get("tools", [])
            logger.info(f"Found {len(tools)} tools")
            results["tools_discovered"] = len(tools)
        else:
            logger.warning("Could not discover tools")
            results["tools_discovered"] = 0

        # Run prompt injection tests
        if include_prompt_injection and tools:
            logger.info("Running prompt injection tests...")
            injection_results = []
            
            for tool in tools[:5]:  # Test first 5 tools
                tool_name = tool.get("name", "")
                logger.info(f"Testing tool: {tool_name}")
                
                # Get tool parameters
                input_schema = tool.get("inputSchema", {})
                properties = input_schema.get("properties", {})
                
                if properties:
                    # Test ALL parameters in this tool
                    for param_name in properties.keys():
                        logger.info(f"  └─ Testing parameter: {param_name}")
                        
                        tool_results = await self.prompt_injector.test_tool(
                            tool_name=tool_name,
                            parameter_name=param_name,
                            tool_schema=tool,
                        )
                        injection_results.extend(tool_results)
            
            results["prompt_injection"] = self.prompt_injector.generate_report(injection_results)
            results["tests_run"].append("prompt_injection")

        # Run penetration tests
        if include_pentest:
            logger.info("Running penetration tests...")
            pentest_results = await self.pentest.run_all_tests()
            results["penetration_testing"] = self.pentest.generate_report(pentest_results)
            results["tests_run"].append("penetration_testing")

        # Generate overall summary
        results["summary"] = self._generate_summary(results)
        
        logger.info(f"Scan complete (ID: {scan_id})")
        return results

    async def quick_scan(self) -> Dict[str, Any]:
        """
        Run a quick security scan with basic checks
        
        Returns:
            Dictionary containing quick scan results
        """
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        logger.info(f"Starting quick security scan (ID: {scan_id})")
        
        results = {
            "scan_id": scan_id,
            "target": self.base_url,
            "timestamp": datetime.now().isoformat(),
            "scan_type": "quick",
        }

        # Basic connectivity check
        logger.info("Checking connectivity...")
        tools_response = await self.client.list_tools()
        results["connectivity"] = {
            "success": tools_response.success,
            "status_code": tools_response.status_code,
        }

        # Check for common vulnerabilities
        logger.info("Checking for common vulnerabilities...")
        
        # Authentication check
        auth_result = await self.pentest.test_missing_authentication(
            self.pentest.tests[0]  # Missing Authentication test
        )
        results["authentication"] = {
            "vulnerable": auth_result.vulnerable,
            "details": auth_result.details,
        }

        # Information disclosure check
        info_result = await self.pentest.test_information_disclosure(
            self.pentest.tests[-1]  # Information Disclosure test
        )
        results["information_disclosure"] = {
            "vulnerable": info_result.vulnerable,
            "details": info_result.details,
        }

        # Generate summary
        vulnerabilities_found = sum(
            1 for key in ["authentication", "information_disclosure"]
            if results.get(key, {}).get("vulnerable", False)
        )
        
        results["summary"] = {
            "vulnerabilities_found": vulnerabilities_found,
            "risk_level": self._determine_risk_level(vulnerabilities_found),
        }
        
        logger.info(f"Quick scan complete (ID: {scan_id})")
        return results

    async def scan_specific_tool(
        self,
        tool_name: str,
        parameter_name: str,
        test_types: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Scan a specific tool for vulnerabilities
        
        Args:
            tool_name: Name of the tool to scan
            parameter_name: Name of the parameter to test
            test_types: Types of tests to run (None = all)
            
        Returns:
            Dictionary containing scan results
        """
        scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        logger.info(f"Scanning tool '{tool_name}' (ID: {scan_id})")
        
        results = {
            "scan_id": scan_id,
            "target": self.base_url,
            "tool_name": tool_name,
            "parameter_name": parameter_name,
            "timestamp": datetime.now().isoformat(),
        }

        # Convert test types to InjectionType enums
        injection_types = None
        if test_types:
            injection_types = []
            for test_type in test_types:
                try:
                    injection_types.append(InjectionType(test_type))
                except ValueError:
                    logger.warning(f"Unknown test type: {test_type}")

        # Get tool schema to extract required parameters
        tool_schema = None
        tools_response = await self.client.list_tools()
        if tools_response.success:
            tools = tools_response.data.get("tools", [])
            for tool in tools:
                if tool.get("name") == tool_name:
                    tool_schema = tool
                    break
        
        # Run prompt injection tests
        logger.info("Running prompt injection tests...")
        injection_results = await self.prompt_injector.test_tool(
            tool_name=tool_name,
            parameter_name=parameter_name,
            tool_schema=tool_schema,
            payload_types=injection_types,
        )
        
        results["injection_tests"] = self.prompt_injector.generate_report(injection_results)
        
        logger.info(f"Tool scan complete (ID: {scan_id})")
        return results

    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate overall summary from scan results"""
        summary = {
            "tests_run": results.get("tests_run", []),
            "total_vulnerabilities": 0,
            "critical_vulnerabilities": 0,
            "high_vulnerabilities": 0,
            "risk_level": "unknown",
        }

        # Count prompt injection vulnerabilities
        if "prompt_injection" in results:
            pi_summary = results["prompt_injection"]["summary"]
            injections_succeeded = pi_summary.get("injections_succeeded", 0)
            summary["total_vulnerabilities"] += injections_succeeded
            
            # Count by severity
            by_severity = results["prompt_injection"].get("by_severity", {})
            summary["critical_vulnerabilities"] += by_severity.get("critical", {}).get("succeeded", 0)
            summary["high_vulnerabilities"] += by_severity.get("high", {}).get("succeeded", 0)

        # Count penetration test vulnerabilities
        if "penetration_testing" in results:
            pt_summary = results["penetration_testing"]["summary"]
            vulns_found = pt_summary.get("vulnerabilities_found", 0)
            summary["total_vulnerabilities"] += vulns_found
            
            # Count by severity
            by_severity = results["penetration_testing"].get("by_severity", {})
            summary["critical_vulnerabilities"] += by_severity.get("critical", {}).get("vulnerable", 0)
            summary["high_vulnerabilities"] += by_severity.get("high", {}).get("vulnerable", 0)

        # Determine risk level
        summary["risk_level"] = self._determine_risk_level(
            summary["total_vulnerabilities"],
            summary["critical_vulnerabilities"],
            summary["high_vulnerabilities"],
        )

        return summary

    def _determine_risk_level(
        self,
        total_vulns: int,
        critical_vulns: int = 0,
        high_vulns: int = 0,
    ) -> str:
        """Determine overall risk level"""
        if critical_vulns > 0:
            return "CRITICAL"
        elif high_vulns > 2:
            return "HIGH"
        elif high_vulns > 0 or total_vulns > 5:
            return "MEDIUM"
        elif total_vulns > 0:
            return "LOW"
        else:
            return "MINIMAL"

    def save_report(
        self,
        results: Dict[str, Any],
        output_path: str,
        format: str = "json",
    ):
        """
        Save scan report to file
        
        Args:
            results: Scan results dictionary
            output_path: Path to save the report
            format: Report format (json, html, txt)
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        if format == "json":
            with open(output_file, "w") as f:
                json.dump(results, f, indent=2)
            logger.info(f"Report saved to {output_file}")
        
        elif format == "txt":
            with open(output_file, "w") as f:
                f.write(self._format_text_report(results))
            logger.info(f"Report saved to {output_file}")
        
        else:
            logger.error(f"Unsupported format: {format}")

    def _format_text_report(self, results: Dict[str, Any]) -> str:
        """Format results as text report"""
        lines = []
        lines.append("=" * 80)
        lines.append("MCP SECURITY SCAN REPORT")
        lines.append("=" * 80)
        lines.append(f"Scan ID: {results.get('scan_id', 'N/A')}")
        lines.append(f"Target: {results.get('target', 'N/A')}")
        lines.append(f"Timestamp: {results.get('timestamp', 'N/A')}")
        lines.append("")
        
        # Summary
        summary = results.get("summary", {})
        lines.append("SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Risk Level: {summary.get('risk_level', 'N/A')}")
        lines.append(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        lines.append(f"Critical: {summary.get('critical_vulnerabilities', 0)}")
        lines.append(f"High: {summary.get('high_vulnerabilities', 0)}")
        lines.append("")
        
        # Prompt Injection Results
        if "prompt_injection" in results:
            lines.append("PROMPT INJECTION TESTS")
            lines.append("-" * 80)
            pi = results["prompt_injection"]["summary"]
            lines.append(f"Total Tests: {pi.get('total_tests', 0)}")
            lines.append(f"Blocked: {pi.get('injections_blocked', 0)}")
            lines.append(f"Succeeded: {pi.get('injections_succeeded', 0)}")
            lines.append(f"Block Rate: {pi.get('block_rate', 'N/A')}")
            lines.append("")
        
        # Penetration Test Results
        if "penetration_testing" in results:
            lines.append("PENETRATION TESTS")
            lines.append("-" * 80)
            pt = results["penetration_testing"]["summary"]
            lines.append(f"Total Tests: {pt.get('total_tests', 0)}")
            lines.append(f"Vulnerabilities Found: {pt.get('vulnerabilities_found', 0)}")
            lines.append(f"Tests Passed: {pt.get('tests_passed', 0)}")
            lines.append(f"Security Score: {pt.get('security_score', 'N/A')}")
            lines.append("")
        
        lines.append("=" * 80)
        return "\n".join(lines)
