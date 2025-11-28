#!/usr/bin/env python3
"""
Run comprehensive security scan including prompt injection tests
"""
import asyncio
import json
from mcp_security.client.mcp_client_impl import MCPClient
from mcp_security.attacks.prompt_injection_impl import PromptInjector, InjectionType

async def test_prompt_injections():
    """Test prompt injection attacks"""
    client = MCPClient("https://site-mzf6g.powerappsportals.com/mcp")
    await client.connect()
    
    injector = PromptInjector(client)
    
    # Run prompt injection tests
    results = await injector.test_all_tools()
    
    await client.disconnect()
    
    return results

async def main():
    print("Running comprehensive prompt injection tests...")
    
    results = await test_prompt_injections()
    
    # Analyze results
    total = len(results)
    vulnerable = sum(1 for r in results if r.successful)
    
    print(f"\n✓ Prompt Injection Tests Complete")
    print(f"  Total: {total}")
    print(f"  Vulnerable: {vulnerable}")
    print(f"  Safe: {total - vulnerable}")
    
    # Save detailed results
    output = {
        "total_tests": total,
        "vulnerable": vulnerable,
        "safe": total - vulnerable,
        "results": [
            {
                "tool": r.tool_name,
                "injection_type": r.injection_type.value,
                "payload": r.payload[:100] + "..." if len(r.payload) > 100 else r.payload,
                "successful": r.successful,
                "response": str(r.response)[:200] + "..." if r.response and len(str(r.response)) > 200 else str(r.response),
                "indicators": r.indicators
            }
            for r in results
        ]
    }
    
    with open('prompt_injection_results.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\n✓ Detailed results saved to: prompt_injection_results.json")

if __name__ == '__main__':
    asyncio.run(main())
