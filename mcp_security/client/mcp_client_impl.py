"""
MCP Client for connecting to and interacting with remote MCP servers
"""

import json
import logging
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass
import httpx
import asyncio
from enum import Enum

logger = logging.getLogger(__name__)


class MCPProtocol(Enum):
    """Supported MCP protocols"""
    HTTP = "http"
    HTTPS = "https"
    WS = "ws"
    WSS = "wss"


@dataclass
class MCPResponse:
    """Response from MCP server"""
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    status_code: Optional[int] = None
    headers: Optional[Dict[str, str]] = None
    raw_response: Optional[str] = None


class MCPClient:
    """
    Client for interacting with MCP servers
    Supports both HTTP and WebSocket connections
    """

    def __init__(
        self,
        base_url: str,
        timeout: int = 30,
        headers: Optional[Dict[str, str]] = None,
        verify_ssl: bool = True,
    ):
        """
        Initialize MCP client
        
        Args:
            base_url: Base URL of the MCP server
            timeout: Request timeout in seconds
            headers: Additional headers to send with requests
            verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.headers = headers or {}
        self.session: Optional[httpx.AsyncClient] = None
        
    async def __aenter__(self):
        """Async context manager entry"""
        await self.connect()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()
        
    async def connect(self):
        """Establish connection to MCP server"""
        default_headers = {
            "Content-Type": "application/json",
        }
        default_headers.update(self.headers)
        
        logger.info(f"Creating session with headers: {default_headers}")
        self.session = httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_ssl,
            headers=default_headers,
        )
        logger.info(f"Connected to MCP server: {self.base_url}")
    
    async def initialize(self) -> MCPResponse:
        """
        Initialize connection with MCP server
        Performs the MCP protocol handshake
        
        Returns:
            MCPResponse with initialization result
        """
        endpoints = [
            f"{self.base_url}/",
            f"{self.base_url}/mcp",
        ]
        
        payload = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "roots": {"listChanged": True},
                    "sampling": {}
                },
                "clientInfo": {
                    "name": "mcp-security-scanner",
                    "version": "1.0.0"
                }
            },
            "id": 1
        }
        
        last_error = None
        
        for endpoint in endpoints:
            try:
                logger.debug(f"Initializing MCP at: {endpoint}")
                response = await self.session.post(endpoint, json=payload)
                
                if response.status_code == 200:
                    data = response.json()
                    if "result" in data:
                        logger.info(f"MCP initialized successfully at: {endpoint}")
                        return MCPResponse(
                            success=True,
                            data=data.get("result", {}),
                            status_code=response.status_code,
                            headers=dict(response.headers),
                            raw_response=response.text,
                        )
                else:
                    last_error = f"HTTP {response.status_code}"
                    logger.debug(f"Initialize failed at {endpoint}: {response.status_code}")
            except Exception as e:
                last_error = str(e)
                logger.debug(f"Initialize failed at {endpoint}: {e}")
                continue
        
        return MCPResponse(
            success=False,
            error=f"Could not initialize MCP connection. Last error: {last_error}"
        )
        
    async def close(self):
        """Close connection to MCP server"""
        if self.session:
            await self.session.aclose()
            self.session = None
            logger.info("Closed connection to MCP server")
    
    async def list_tools(self) -> MCPResponse:
        """
        List all available tools on the MCP server
        Uses proper MCP protocol format
        
        Returns:
            MCPResponse with list of tools
        """
        # Try multiple endpoint patterns
        endpoints = [
            f"{self.base_url}/",
        ]
        
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {},
            "id": 2
        }
        
        last_error = None
        last_response_text = None
        
        for endpoint in endpoints:
            try:
                logger.debug(f"Listing tools at: {endpoint}")
                response = await self.session.post(endpoint, json=payload)
                
                if response.status_code == 200:
                    data = response.json()
                    if "result" in data:
                        logger.info(f"Tools listed successfully from: {endpoint}")
                        return MCPResponse(
                            success=True,
                            data=data.get("result", {}),
                            status_code=response.status_code,
                            headers=dict(response.headers),
                            raw_response=response.text,
                        )
                    elif "error" in data:
                        last_error = data["error"].get("message", "Unknown error")
                        logger.debug(f"MCP error at {endpoint}: {last_error}")
                else:
                    last_error = f"HTTP {response.status_code}"
                    last_response_text = response.text[:200]
                    logger.debug(f"Endpoint {endpoint} returned {response.status_code}")
            except Exception as e:
                last_error = str(e)
                logger.debug(f"Endpoint {endpoint} failed: {e}")
                continue
        
        logger.error(f"All endpoints failed. Last error: {last_error}")
        return MCPResponse(
            success=False,
            error=f"Could not list tools. Last error: {last_error}"
        )
    
    async def call_tool(
        self,
        tool_name: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> MCPResponse:
        """
        Call a specific tool on the MCP server
        
        Args:
            tool_name: Name of the tool to call
            arguments: Arguments to pass to the tool
            
        Returns:
            MCPResponse with tool execution result
        """
        # Use the same endpoint pattern that worked for initialize and list_tools
        endpoints = [
            f"{self.base_url}/",  # Standard MCP endpoint
        ]
        
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments or {},
            },
            "id": 4,  # Unique ID for this request type
        }
        
        last_error = None
        last_status = None
        
        # Log headers before making request
        if self.session and self.session.headers:
            logger.info(f"[TOOL_CALL] Calling '{tool_name}' with session headers: {dict(self.session.headers)}")
        else:
            logger.warning(f"[TOOL_CALL] No session headers available for '{tool_name}'!")
        
        for endpoint in endpoints:
            try:
                logger.info(f"Calling tool '{tool_name}' at: {endpoint}")
                response = await self.session.post(endpoint, json=payload)
                last_status = response.status_code
                
                logger.debug(f"Response status: {response.status_code}")
                logger.debug(f"Response body: {response.text[:500]}")
                
                if response.status_code == 401:
                    logger.error(f"401 Unauthorized - Response: {response.text[:1000]}")
                    logger.error(f"Request headers sent: {dict(self.session.headers)}")
                
                if response.status_code == 200:
                    data = response.json()
                    if "result" in data:
                        logger.info(f"Tool '{tool_name}' called successfully at: {endpoint}")
                        return MCPResponse(
                            success=True,
                            data=data.get("result", {}),
                            status_code=response.status_code,
                            headers=dict(response.headers),
                            raw_response=response.text,
                        )
                    elif "error" in data:
                        # JSON-RPC error response
                        error_info = data.get("error", {})
                        error_code = error_info.get("code", 0)
                        error_msg = error_info.get("message", "Unknown error")
                        last_error = f"[{error_code}] {error_msg}"
                        logger.warning(f"Tool call returned JSON-RPC error: {last_error}")
                        
                        # If method not found, the server doesn't support tools/call
                        if error_code == -32601:
                            logger.error(f"Server does not implement 'tools/call' method")
                            return MCPResponse(
                                success=False,
                                error=f"Server does not support tool execution (tools/call method not implemented)",
                                status_code=response.status_code
                            )
                        continue
                elif response.status_code == 404:
                    last_error = f"Endpoint not found (HTTP 404). Server may not implement tools/call."
                    logger.warning(f"Tool call endpoint returned 404: {endpoint}")
                else:
                    last_error = f"HTTP {response.status_code}: {response.text[:200]}"
                    logger.debug(f"Tool call failed at {endpoint}: {response.status_code}")
            except Exception as e:
                last_error = str(e)
                logger.debug(f"Tool call failed at {endpoint}: {e}")
                continue
        
        error_msg = f"Could not call tool '{tool_name}'. Last error: {last_error}"
        if last_status == 404:
            error_msg += "\n\nThis MCP server may not implement the tools/call method. It can list tools but cannot execute them."
        
        return MCPResponse(
            success=False,
            error=error_msg,
            status_code=last_status
        )
    
    async def get_prompt(self, prompt_name: str, arguments: Dict[str, Any] = None) -> MCPResponse:
        """
        Get a prompt template from the MCP server
        
        Args:
            prompt_name: Name of the prompt to retrieve
            arguments: Optional arguments for the prompt
            
        Returns:
            MCPResponse with prompt template
        """
        endpoints = [
            f"{self.base_url}/prompts/get",
            f"{self.base_url}/",
        ]
        
        payload = {
            "jsonrpc": "2.0",
            "method": "prompts/get",
            "params": {"name": prompt_name, "arguments": arguments or {}},
            "id": 1,
        }
        
        last_error = None
        
        for endpoint in endpoints:
            try:
                logger.debug(f"Getting prompt at: {endpoint}")
                response = await self.session.post(endpoint, json=payload)
                
                if response.status_code == 200:
                    data = response.json()
                    if "result" in data:
                        return MCPResponse(
                            success=True,
                            data=data.get("result", {}),
                            status_code=response.status_code,
                            headers=dict(response.headers),
                            raw_response=response.text,
                        )
                else:
                    last_error = f"HTTP {response.status_code}"
                    logger.debug(f"Get prompt failed at {endpoint}: {response.status_code}")
            except Exception as e:
                last_error = str(e)
                logger.debug(f"Get prompt failed at {endpoint}: {e}")
                continue
        
        return MCPResponse(
            success=False,
            error=f"Could not get prompt '{prompt_name}'. Last error: {last_error}"
        )
    
    async def list_resources(self) -> MCPResponse:
        """
        List all available resources on the MCP server
        Uses proper MCP protocol format
        
        Note: Resources are optional in MCP - not all servers implement this.
        
        Returns:
            MCPResponse with list of resources (or empty list if not supported)
        """
        endpoints = [
            f"{self.base_url}/",
        ]
        
        payload = {
            "jsonrpc": "2.0",
            "method": "resources/list",
            "params": {},
            "id": 3
        }
        
        last_error = None
        
        for endpoint in endpoints:
            try:
                logger.debug(f"Listing resources at: {endpoint}")
                response = await self.session.post(endpoint, json=payload)
                
                if response.status_code == 200:
                    data = response.json()
                    if "result" in data:
                        logger.info(f"Resources listed successfully from: {endpoint}")
                        return MCPResponse(
                            success=True,
                            data=data.get("result", {}),
                            status_code=response.status_code,
                            headers=dict(response.headers),
                            raw_response=response.text,
                        )
                    elif "error" in data:
                        error_code = data["error"].get("code", 0)
                        error_msg = data["error"].get("message", "Unknown error")
                        
                        # Method not found (-32601) means resources aren't supported
                        if error_code == -32601 or "not found" in error_msg.lower():
                            logger.info(f"Resources not supported by server (this is optional in MCP)")
                            return MCPResponse(
                                success=True,
                                data={"resources": []},
                                status_code=response.status_code,
                                headers=dict(response.headers),
                                raw_response=response.text,
                            )
                        
                        last_error = error_msg
                        logger.debug(f"MCP error at {endpoint}: {last_error}")
                else:
                    last_error = f"HTTP {response.status_code}"
                    logger.debug(f"Endpoint {endpoint} returned {response.status_code}")
            except Exception as e:
                last_error = str(e)
                logger.debug(f"Endpoint {endpoint} failed: {e}")
                continue
        
        # If all endpoints failed with non-method-not-found errors, return error
        logger.warning(f"Could not list resources. Last error: {last_error}")
        # Return success with empty list - resources are optional
        return MCPResponse(
            success=True,
            data={"resources": []},
            error=f"Could not list resources. Last error: {last_error}"
        )
    
    async def read_resource(self, resource_uri: str) -> MCPResponse:
        """
        Read a specific resource from the MCP server
        
        Args:
            resource_uri: URI of the resource to read
            
        Returns:
            MCPResponse with resource content
        """
        endpoints = [
            f"{self.base_url}/resources/read",
            f"{self.base_url}/",
        ]
        
        payload = {
            "jsonrpc": "2.0",
            "method": "resources/read",
            "params": {"uri": resource_uri},
            "id": 1,
        }
        
        last_error = None
        
        for endpoint in endpoints:
            try:
                logger.debug(f"Reading resource at: {endpoint}")
                response = await self.session.post(endpoint, json=payload)
                
                if response.status_code == 200:
                    data = response.json()
                    if "result" in data:
                        return MCPResponse(
                            success=True,
                            data=data.get("result", {}),
                            status_code=response.status_code,
                            headers=dict(response.headers),
                            raw_response=response.text,
                        )
                else:
                    last_error = f"HTTP {response.status_code}"
                    logger.debug(f"Read resource failed at {endpoint}: {response.status_code}")
            except Exception as e:
                last_error = str(e)
                logger.debug(f"Read resource failed at {endpoint}: {e}")
                continue
        
        return MCPResponse(
            success=False,
            error=f"Could not read resource '{resource_uri}'. Last error: {last_error}"
        )
    
    async def test_connectivity(self) -> MCPResponse:
        """
        Test basic connectivity to the MCP server
        Tries common endpoints to verify server is reachable
        
        Returns:
            MCPResponse with connectivity status
        """
        endpoints = [
            f"{self.base_url}/",
            f"{self.base_url}/health",
            f"{self.base_url}/api/health",
        ]
        
        for endpoint in endpoints:
            try:
                logger.debug(f"Testing connectivity to: {endpoint}")
                response = await self.session.get(endpoint, timeout=10)
                
                if response.status_code < 500:  # Any response except 5xx is good
                    logger.info(f"Server is reachable at: {endpoint}")
                    return MCPResponse(
                        success=True,
                        data={"reachable": True, "endpoint": endpoint},
                        status_code=response.status_code,
                    )
            except Exception as e:
                logger.debug(f"Connectivity test failed for {endpoint}: {e}")
                continue
        
        return MCPResponse(
            success=False,
            error="Server is not reachable at any known endpoint"
        )
