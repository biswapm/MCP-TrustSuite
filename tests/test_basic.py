"""
Test suite for MCP Security Testing Framework
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch

from mcp_security.client.mcp_client_impl import MCPClient, MCPResponse
from mcp_security.attacks.prompt_injection_impl import PromptInjector, InjectionType
from mcp_security.attacks.pentest import PenetrationTester


class TestMCPClient:
    """Test MCP Client"""
    
    @pytest.mark.asyncio
    async def test_client_initialization(self):
        """Test client initialization"""
        client = MCPClient(base_url="http://localhost:3000")
        assert client.base_url == "http://localhost:3000"
        assert client.timeout == 30
        assert client.verify_ssl == True
    
    @pytest.mark.asyncio
    async def test_list_tools(self):
        """Test listing tools"""
        client = MCPClient(base_url="http://localhost:3000")
        await client.connect()
        
        # Mock response
        with patch.object(client.session, 'post') as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "result": {"tools": [{"name": "test_tool"}]}
            }
            mock_response.text = "{}"
            mock_response.headers = {}
            mock_post.return_value = mock_response
            
            response = await client.list_tools()
            
            assert response.success == True
            assert "tools" in response.data
        
        await client.close()


class TestPromptInjector:
    """Test Prompt Injection module"""
    
    def test_payload_loading(self):
        """Test that payloads are loaded correctly"""
        mock_client = Mock(spec=MCPClient)
        injector = PromptInjector(mock_client)
        
        assert len(injector.payloads) > 0
        
        # Check that all injection types are represented
        types = set(p.type for p in injector.payloads)
        assert InjectionType.CONTEXT_BREAKING in types
        assert InjectionType.INSTRUCTION_OVERRIDE in types
        assert InjectionType.ROLE_MANIPULATION in types
    
    @pytest.mark.asyncio
    async def test_injection_test(self):
        """Test running injection test"""
        mock_client = Mock(spec=MCPClient)
        mock_client.call_tool = AsyncMock(return_value=MCPResponse(
            success=True,
            data={"result": "blocked"},
            status_code=200
        ))
        
        injector = PromptInjector(mock_client)
        
        results = await injector.test_tool(
            tool_name="test_tool",
            parameter_name="input",
            payload_types=[InjectionType.CONTEXT_BREAKING]
        )
        
        assert len(results) > 0
        assert all(hasattr(r, 'payload') for r in results)


class TestPenetrationTester:
    """Test Penetration Testing module"""
    
    def test_test_loading(self):
        """Test that vulnerability tests are loaded correctly"""
        mock_client = Mock(spec=MCPClient)
        tester = PenetrationTester(mock_client)
        
        assert len(tester.tests) > 0
        
        # Check test names
        test_names = [t.name for t in tester.tests]
        assert "Missing Authentication" in test_names
        assert "Command Injection" in test_names


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
