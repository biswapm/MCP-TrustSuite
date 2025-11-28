"""
Launch script for MCP Security Testing Framework
Provides easy access to both CLI and Web UI
"""

import sys
import subprocess
from pathlib import Path


def print_banner():
    banner = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   🔒 MCP Eval - Security Evaluation Framework                    ║
║                                                                   ║
║   Comprehensive security testing for MCP servers                 ║
║   Version 0.1.0                                                  ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_menu():
    menu = """
Choose an option:

  1. 🌐 Launch Web UI (Recommended)
  2. 💻 Use CLI - Full Scan
  3. 💻 Use CLI - Quick Scan
  4. 💻 Use CLI - Prompt Injection Test
  5. 💻 Use CLI - Penetration Test
  6. 🔍 Use CLI - Discover Server
  7. 📚 View Documentation
  8. ❌ Exit

⚠️  Remember: For authorized security testing only!
    """
    print(menu)


def launch_web_ui():
    print("\n🌐 Starting Web UI...")
    print("=" * 70)
    print("The web interface will open at: http://localhost:8000")
    print("Press Ctrl+C to stop the server")
    print("=" * 70 + "\n")
    
    try:
        subprocess.run([
            sys.executable, "-m", "uvicorn",
            "mcp_security.web_ui:app",
            "--host", "0.0.0.0",
            "--port", "8000"
        ])
    except KeyboardInterrupt:
        print("\n\n✅ Web UI stopped")


def run_cli_command(args):
    try:
        subprocess.run([sys.executable, "-m", "mcp_security"] + args)
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted")


def main():
    print_banner()
    
    while True:
        print_menu()
        
        try:
            choice = input("Enter your choice (1-8): ").strip()
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            sys.exit(0)
        
        if choice == "1":
            launch_web_ui()
        
        elif choice == "2":
            url = input("Enter target URL (e.g., http://localhost:3000): ").strip()
            if url:
                print(f"\n🔍 Running full scan on {url}...\n")
                run_cli_command(["scan", "--url", url])
        
        elif choice == "3":
            url = input("Enter target URL: ").strip()
            if url:
                print(f"\n⚡ Running quick scan on {url}...\n")
                run_cli_command(["scan", "--url", url, "--quick"])
        
        elif choice == "4":
            url = input("Enter target URL: ").strip()
            tool = input("Enter tool name: ").strip()
            param = input("Enter parameter name: ").strip()
            if url and tool and param:
                print(f"\n💉 Testing {tool} for prompt injection...\n")
                run_cli_command([
                    "inject",
                    "--url", url,
                    "--tool", tool,
                    "--parameter", param
                ])
        
        elif choice == "5":
            url = input("Enter target URL: ").strip()
            if url:
                print(f"\n🛡️  Running penetration tests on {url}...\n")
                run_cli_command(["pentest", "--url", url])
        
        elif choice == "6":
            url = input("Enter target URL: ").strip()
            if url:
                print(f"\n🔍 Discovering server at {url}...\n")
                run_cli_command(["discover", "--url", url])
        
        elif choice == "7":
            print("\n📚 Documentation:")
            print("  - README.md - Main documentation")
            print("  - QUICKSTART.md - Quick start guide")
            print("  - WEB_UI.md - Web interface documentation")
            print("  - PROJECT_OVERVIEW.md - Technical details")
            print("\n  Visit: https://github.com/your-repo")
            input("\nPress Enter to continue...")
        
        elif choice == "8":
            print("\n👋 Thank you for using MCP Eval!")
            print("   Remember: Test responsibly and ethically.\n")
            sys.exit(0)
        
        else:
            print("\n❌ Invalid choice. Please try again.\n")
        
        print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    main()
