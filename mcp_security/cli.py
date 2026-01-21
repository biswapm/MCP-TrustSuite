"""
CLI Interface for MCP Security Testing
"""

import click
import asyncio
import logging
import json
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from pathlib import Path

from mcp_security.scanner.security_scanner_impl import SecurityScanner
from mcp_security.client.mcp_client_impl import MCPClient
from mcp_security.attacks.prompt_injection_impl import PromptInjector
from mcp_security.attacks.pentest import PenetrationTester

console = Console()


def setup_logging(verbose: bool):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """MCP Eval - Evaluate MCP servers for security vulnerabilities"""
    pass


@cli.command()
@click.option('--url', required=True, help='URL of the MCP server')
@click.option('--output', '-o', default='reports/scan_report.json', help='Output file path')
@click.option('--format', '-f', type=click.Choice(['json', 'txt', 'docx']), default='json', help='Output format')
@click.option('--quick', is_flag=True, help='Run quick scan only')
@click.option('--no-prompt-injection', is_flag=True, help='Skip prompt injection tests')
@click.option('--no-pentest', is_flag=True, help='Skip penetration tests')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(url, output, format, quick, no_prompt_injection, no_pentest, verbose):
    """Run security scan on MCP server"""
    setup_logging(verbose)
    
    console.print(f"\n[bold cyan]MCP Eval[/bold cyan]")
    console.print(f"Target: {url}\n")
    
    async def run_scan():
        scanner = SecurityScanner(base_url=url)
        
        try:
            await scanner.initialize()
            
            if quick:
                console.print("[yellow]Running quick scan...[/yellow]")
                results = await scanner.quick_scan()
            else:
                console.print("[yellow]Running full scan...[/yellow]")
                with Progress() as progress:
                    task = progress.add_task("[cyan]Scanning...", total=100)
                    
                    results = await scanner.run_full_scan(
                        include_prompt_injection=not no_prompt_injection,
                        include_pentest=not no_pentest,
                    )
                    
                    progress.update(task, completed=100)
            
            # Display summary
            summary = results.get("summary", {})
            
            table = Table(title="Scan Summary")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="magenta")
            
            table.add_row("Risk Level", summary.get("risk_level", "N/A"))
            table.add_row("Total Vulnerabilities", str(summary.get("total_vulnerabilities", 0)))
            table.add_row("Critical", str(summary.get("critical_vulnerabilities", 0)))
            table.add_row("High", str(summary.get("high_vulnerabilities", 0)))
            
            console.print(table)
            
            # Save report
            scanner.save_report(results, output, format)
            console.print(f"\n[green]✓ Report saved to: {output}[/green]")
            
        finally:
            await scanner.cleanup()
    
    asyncio.run(run_scan())


@cli.command()
@click.option('--url', required=True, help='URL of the MCP server')
@click.option('--tool', required=True, help='Tool name to test')
@click.option('--parameter', required=True, help='Parameter name to inject')
@click.option('--output', '-o', default='reports/injection_report.json', help='Output file path')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def inject(url, tool, parameter, output, verbose):
    """Run prompt injection tests on specific tool"""
    setup_logging(verbose)
    
    console.print(f"\n[bold cyan]Prompt Injection Testing[/bold cyan]")
    console.print(f"Target: {url}")
    console.print(f"Tool: {tool}")
    console.print(f"Parameter: {parameter}\n")
    
    async def run_injection_test():
        client = MCPClient(base_url=url)
        
        try:
            await client.connect()
            injector = PromptInjector(client)
            
            # Get tool schema to extract required parameters
            tool_schema = None
            tools_response = await client.list_tools()
            if tools_response.success:
                tools = tools_response.data.get("tools", [])
                for t in tools:
                    if t.get("name") == tool:
                        tool_schema = t
                        break
            
            console.print("[yellow]Running injection tests...[/yellow]")
            results = await injector.test_tool(tool, parameter, tool_schema=tool_schema)
            
            report = injector.generate_report(results)
            
            # Display summary
            summary = report["summary"]
            
            table = Table(title="Injection Test Summary")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="magenta")
            
            table.add_row("Total Tests", str(summary["total_tests"]))
            table.add_row("Blocked", str(summary["injections_blocked"]))
            table.add_row("Succeeded", str(summary["injections_succeeded"]))
            table.add_row("Block Rate", summary["block_rate"])
            
            console.print(table)
            
            # Save report
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            with open(output, 'w') as f:
                json.dump(report, f, indent=2)
            
            console.print(f"\n[green]✓ Report saved to: {output}[/green]")
            
        finally:
            await client.close()
    
    asyncio.run(run_injection_test())


@cli.command()
@click.option('--url', required=True, help='URL of the MCP server')
@click.option('--output', '-o', default='reports/pentest_report.json', help='Output file path')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def pentest(url, output, verbose):
    """Run penetration tests on MCP server"""
    setup_logging(verbose)
    
    console.print(f"\n[bold cyan]Penetration Testing[/bold cyan]")
    console.print(f"Target: {url}\n")
    
    async def run_pentest():
        client = MCPClient(base_url=url)
        
        try:
            await client.connect()
            tester = PenetrationTester(client)
            
            console.print("[yellow]Running penetration tests...[/yellow]")
            results = await tester.run_all_tests()
            
            report = tester.generate_report(results)
            
            # Display summary
            summary = report["summary"]
            
            table = Table(title="Penetration Test Summary")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="magenta")
            
            table.add_row("Total Tests", str(summary["total_tests"]))
            table.add_row("Vulnerabilities Found", str(summary["vulnerabilities_found"]))
            table.add_row("Tests Passed", str(summary["tests_passed"]))
            table.add_row("Security Score", summary["security_score"])
            
            console.print(table)
            
            # Display vulnerabilities
            if summary["vulnerabilities_found"] > 0:
                vuln_table = Table(title="Vulnerabilities Found", show_header=True)
                vuln_table.add_column("Test", style="cyan")
                vuln_table.add_column("Severity", style="yellow")
                vuln_table.add_column("Details", style="red")
                
                for result in report["results"]:
                    if result["vulnerable"]:
                        vuln_table.add_row(
                            result["test_name"],
                            result["severity"],
                            result["details"][:60] + "..." if len(result["details"]) > 60 else result["details"]
                        )
                
                console.print(vuln_table)
            
            # Save report
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            with open(output, 'w') as f:
                json.dump(report, f, indent=2)
            
            console.print(f"\n[green]✓ Report saved to: {output}[/green]")
            
        finally:
            await client.close()
    
    asyncio.run(run_pentest())


@cli.command()
@click.option('--url', required=True, help='URL of the MCP server')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def discover(url, verbose):
    """Discover available tools and resources on MCP server"""
    setup_logging(verbose)
    
    console.print(f"\n[bold cyan]MCP Server Discovery[/bold cyan]")
    console.print(f"Target: {url}\n")
    
    async def run_discovery():
        client = MCPClient(base_url=url)
        
        try:
            await client.connect()
            
            # List tools
            console.print("[yellow]Discovering tools...[/yellow]")
            tools_response = await client.list_tools()
            
            if tools_response.success and tools_response.data:
                tools = tools_response.data.get("tools", [])
                
                if tools:
                    table = Table(title=f"Tools Found ({len(tools)})")
                    table.add_column("Name", style="cyan")
                    table.add_column("Description", style="white")
                    
                    for tool in tools:
                        name = tool.get("name", "N/A")
                        desc = tool.get("description", "No description")
                        table.add_row(name, desc[:60] + "..." if len(desc) > 60 else desc)
                    
                    console.print(table)
                else:
                    console.print("[yellow]No tools found[/yellow]")
            else:
                console.print(f"[red]Failed to list tools: {tools_response.error}[/red]")
            
            # List resources (optional feature)
            console.print("\n[yellow]Discovering resources...[/yellow]")
            resources_response = await client.list_resources()
            
            if resources_response.success and resources_response.data:
                resources = resources_response.data.get("resources", [])
                
                if resources:
                    table = Table(title=f"Resources Found ({len(resources)})")
                    table.add_column("URI", style="cyan")
                    table.add_column("Name", style="white")
                    
                    for resource in resources:
                        uri = resource.get("uri", "N/A")
                        name = resource.get("name", "N/A")
                        table.add_row(uri, name)
                    
                    console.print(table)
                else:
                    console.print("[dim]No resources found (server may not support resources)[/dim]")
            else:
                console.print(f"[dim]Resources not available: {resources_response.error}[/dim]")
            
        finally:
            await client.close()
    
    asyncio.run(run_discovery())


def main():
    """Main entry point"""
    cli()


if __name__ == "__main__":
    main()
