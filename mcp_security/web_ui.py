"""
Web UI for MCP Security Testing Framework
FastAPI-based web interface with real-time reporting
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
import httpx

from mcp_security.scanner.security_scanner_impl import SecurityScanner
from mcp_security.client.mcp_client_impl import MCPClient
from mcp_security.attacks.prompt_injection_impl import PromptInjector
from mcp_security.attacks.pentest import PenetrationTester

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="MCP Security Testing Framework", version="0.1.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Store active scans and SSE clients
active_scans: Dict[str, Dict[str, Any]] = {}
sse_clients: List[asyncio.Queue] = []


class ScanRequest(BaseModel):
    url: str
    scan_type: str = "full"  # full, quick, injection, pentest
    tool_name: Optional[str] = None
    parameter_name: Optional[str] = None
    selected_tools: Optional[List[str]] = None  # List of specific tools to test (None = all tools)
    timeout: int = 30
    verify_ssl: bool = True
    auth_token: Optional[str] = None  # Bearer token for authentication
    parameter_values: Optional[Dict[str, Dict[str, Any]]] = None  # User-provided parameter values {tool_name: {param_name: value}}
    # LLM Configuration
    enable_llm: bool = True
    llm_provider: str = "openai"  # openai, azure_openai, anthropic, ollama
    llm_api_key: Optional[str] = None
    llm_model: str = "gpt-4"
    azure_endpoint: Optional[str] = None
    azure_api_version: str = "2024-02-15-preview"


class LLMConfig(BaseModel):
    """LLM Configuration settings"""
    provider: str = "openai"  # openai, azure_openai, anthropic, ollama
    api_key: Optional[str] = None
    model: str = "gpt-4"
    enabled: bool = True
    azure_endpoint: Optional[str] = None
    azure_api_version: str = "2024-02-15-preview"


class EventBroadcaster:
    """Manage SSE clients"""
    
    def __init__(self):
        self.clients: List[asyncio.Queue] = []
    
    def add_client(self, queue: asyncio.Queue):
        self.clients.append(queue)
        logger.info(f"SSE client connected. Total clients: {len(self.clients)}")
    
    def remove_client(self, queue: asyncio.Queue):
        if queue in self.clients:
            self.clients.remove(queue)
        logger.info(f"SSE client disconnected. Total clients: {len(self.clients)}")
    
    async def broadcast(self, message: dict):
        """Broadcast message to all connected SSE clients"""
        dead_clients = []
        for client_queue in self.clients:
            try:
                await client_queue.put(message)
            except Exception as e:
                logger.error(f"Error broadcasting to client: {e}")
                dead_clients.append(client_queue)
        
        # Remove dead clients
        for dead_client in dead_clients:
            self.remove_client(dead_client)


broadcaster = EventBroadcaster()


@app.get("/api/events")
async def event_stream(request: Request):
    """Server-Sent Events endpoint for real-time updates"""
    async def event_generator():
        queue = asyncio.Queue()
        broadcaster.add_client(queue)
        
        try:
            while True:
                # Check if client disconnected
                if await request.is_disconnected():
                    break
                
                # Wait for message with timeout
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield f"data: {json.dumps(message)}\n\n"
                except asyncio.TimeoutError:
                    # Send keepalive
                    yield f": keepalive\n\n"
                    
        except asyncio.CancelledError:
            pass
        finally:
            broadcaster.remove_client(queue)
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@app.get("/")
async def read_root():
    """Serve the main UI"""
    return FileResponse("mcp_security/web/index.html")


@app.get("/oauth/callback")
async def oauth_callback(code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None, error_description: Optional[str] = None):
    """OAuth callback endpoint - displays the authorization code for user to copy"""
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>OAuth Authorization Complete</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                margin: 0;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            }
            .container {
                background: white;
                padding: 40px;
                border-radius: 12px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                max-width: 600px;
                width: 90%;
            }
            h1 {
                color: #10b981;
                margin-top: 0;
                font-size: 28px;
            }
            .error h1 {
                color: #dc2626;
            }
            .code-box {
                background: #f3f4f6;
                padding: 20px;
                border-radius: 8px;
                margin: 20px 0;
                border: 2px solid #10b981;
                word-break: break-all;
                font-family: 'Courier New', monospace;
                font-size: 14px;
                position: relative;
            }
            .error .code-box {
                border-color: #dc2626;
                background: #fee2e2;
            }
            .copy-btn {
                background: #10b981;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 16px;
                font-weight: 600;
                margin-top: 16px;
                transition: background 0.2s;
            }
            .copy-btn:hover {
                background: #059669;
            }
            .copy-btn:active {
                transform: scale(0.98);
            }
            .copied {
                background: #059669 !important;
            }
            .instruction {
                color: #6b7280;
                margin: 16px 0;
                line-height: 1.6;
            }
            .label {
                font-weight: 600;
                color: #374151;
                margin-bottom: 8px;
            }
        </style>
    </head>
    <body>
    """
    
    if error:
        html_content += f"""
        <div class="container error">
            <h1>❌ Authorization Failed</h1>
            <div class="label">Error:</div>
            <div class="code-box">{error}</div>
            {f'<div class="label">Description:</div><div class="code-box">{error_description}</div>' if error_description else ''}
            <p class="instruction">Please close this window and try again.</p>
        </div>
        """
    elif code:
        html_content += f"""
        <div class="container">
            <h1>✅ Authorization Successful!</h1>
            <p class="instruction">Copy the authorization code below and paste it into the MCP Security application.</p>
            <div class="label">Authorization Code:</div>
            <div class="code-box" id="codeBox">{code}</div>
            <button class="copy-btn" onclick="copyCode()">📋 Copy Code</button>
            {f'<div style="margin-top: 20px;"><div class="label">State:</div><div class="code-box">{state}</div></div>' if state else ''}
            <p class="instruction" style="margin-top: 24px; font-size: 14px;">You can close this window after copying the code.</p>
        </div>
        <script>
            function copyCode() {{
                const code = document.getElementById('codeBox').textContent;
                navigator.clipboard.writeText(code).then(() => {{
                    const btn = document.querySelector('.copy-btn');
                    btn.textContent = '✓ Copied!';
                    btn.classList.add('copied');
                    setTimeout(() => {{
                        btn.textContent = '📋 Copy Code';
                        btn.classList.remove('copied');
                    }}, 2000);
                }});
            }}
        </script>
        """
    else:
        html_content += """
        <div class="container error">
            <h1>⚠️ Invalid Request</h1>
            <p class="instruction">No authorization code or error received. Please try again.</p>
        </div>
        """
    
    html_content += """
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)


@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": "0.1.0",
        "active_scans": len(active_scans)
    }


@app.post("/api/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a security scan"""
    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    active_scans[scan_id] = {
        "id": scan_id,
        "status": "starting",
        "target": request.url,
        "scan_type": request.scan_type,
        "started_at": datetime.now().isoformat(),
        "progress": 0,
    }
    
    # Broadcast scan started
    await broadcaster.broadcast({
        "type": "scan_started",
        "scan_id": scan_id,
        "target": request.url,
        "scan_type": request.scan_type,
        "verify_ssl": request.verify_ssl,
        "data": active_scans[scan_id]
    })
    
    # Start scan in background
    background_tasks.add_task(run_scan, scan_id, request)
    
    return {
        "scan_id": scan_id,
        "status": "started",
        "message": f"Scan {scan_id} started"
    }


async def run_scan(scan_id: str, request: ScanRequest):
    """Run the actual scan"""
    try:
        active_scans[scan_id]["status"] = "running"
        await broadcaster.broadcast({
            "type": "scan_progress",
            "scan_id": scan_id,
            "progress": 10,
            "message": "Initializing scanner...",
            "details": f"Connecting to {request.url}"
        })
        
        # Create broadcast callback for scanner
        async def broadcast_callback(event: dict):
            await broadcaster.broadcast(event)
        
        # Configure LLM based on request
        from mcp_security.llm.llm_simulator import LLMProvider
        llm_provider_map = {
            "openai": LLMProvider.OPENAI,
            "azure_openai": LLMProvider.AZURE_OPENAI,
            "anthropic": LLMProvider.ANTHROPIC,
            "ollama": LLMProvider.OLLAMA
        }
        
        llm_config = {
            "enable_llm_simulation": request.enable_llm,
            "llm_provider": llm_provider_map.get(request.llm_provider, LLMProvider.OPENAI),
            "llm_api_key": request.llm_api_key,
            "llm_model": request.llm_model,
            "azure_endpoint": request.azure_endpoint,
            "azure_api_version": request.azure_api_version
        }
        
        scanner = SecurityScanner(
            base_url=request.url,
            timeout=request.timeout,
            verify_ssl=request.verify_ssl,
            auth_token=request.auth_token,
            event_callback=broadcast_callback,
            parameter_values=request.parameter_values,
            selected_tools=request.selected_tools,
            **llm_config
        )
        
        await scanner.initialize()
        
        await broadcaster.broadcast({
            "type": "scan_progress",
            "scan_id": scan_id,
            "progress": 20,
            "message": "Connected to server",
            "details": "MCP handshake completed successfully"
        })
        
        # Broadcast tool discovery
        await broadcaster.broadcast({
            "type": "log",
            "level": "info",
            "message": f"🔍 Discovering tools on {request.url}..."
        })
        
        results = None
        
        if request.scan_type == "full":
            await broadcaster.broadcast({
                "type": "scan_progress",
                "scan_id": scan_id,
                "progress": 30,
                "message": "Running full security scan...",
                "details": "Testing all attack vectors and penetration tests"
            })
            await broadcaster.broadcast({
                "type": "log",
                "level": "info",
                "message": "🎯 Starting comprehensive security scan"
            })
            results = await scanner.run_full_scan()
            
        elif request.scan_type == "quick":
            await broadcaster.broadcast({
                "type": "scan_progress",
                "scan_id": scan_id,
                "progress": 30,
                "message": "Running quick scan...",
                "details": "Testing critical attack vectors only"
            })
            await broadcaster.broadcast({
                "type": "log",
                "level": "info",
                "message": "⚡ Starting quick scan (critical tests only)"
            })
            results = await scanner.quick_scan()
            
        elif request.scan_type == "injection" and request.tool_name and request.parameter_name:
            await broadcaster.broadcast({
                "type": "scan_progress",
                "scan_id": scan_id,
                "progress": 30,
                "message": f"Testing {request.tool_name} for prompt injection...",
                "details": f"Parameter: {request.parameter_name}"
            })
            await broadcaster.broadcast({
                "type": "log",
                "level": "info",
                "message": f"💉 Testing prompt injection on {request.tool_name}.{request.parameter_name}"
            })
            results = await scanner.scan_specific_tool(
                request.tool_name,
                request.parameter_name
            )
        
        elif request.scan_type == "pentest":
            await broadcaster.broadcast({
                "type": "scan_progress",
                "scan_id": scan_id,
                "progress": 30,
                "message": "Running penetration tests...",
                "details": "Testing authentication, authorization, and input validation"
            })
            await broadcaster.broadcast({
                "type": "log",
                "level": "info",
                "message": "🔐 Starting penetration tests"
            })
            client = MCPClient(base_url=request.url)
            await client.connect()
            tester = PenetrationTester(client)
            pentest_results = await tester.run_all_tests()
            results = {
                "scan_id": scan_id,
                "target": request.url,
                "timestamp": datetime.now().isoformat(),
                "penetration_testing": tester.generate_report(pentest_results)
            }
            await client.close()
        
        await broadcaster.broadcast({
            "type": "scan_progress",
            "scan_id": scan_id,
            "progress": 90,
            "message": "Generating report...",
            "details": "Analyzing results and creating JSON report"
        })
        
        # Save report
        report_path = f"reports/scan_{scan_id}.json"
        scanner.save_report(results, report_path, format="json")
        
        await broadcaster.broadcast({
            "type": "log",
            "level": "success",
            "message": f"📄 Report saved to {report_path}"
        })
        
        await scanner.cleanup()
        
        active_scans[scan_id].update({
            "status": "completed",
            "progress": 100,
            "completed_at": datetime.now().isoformat(),
            "results": results,
            "report_path": report_path
        })
        
        await broadcaster.broadcast({
            "type": "scan_completed",
            "scan_id": scan_id,
            "results": results,
            "report_path": report_path
        })
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
        active_scans[scan_id].update({
            "status": "failed",
            "error": str(e),
            "completed_at": datetime.now().isoformat()
        })
        
        import traceback
        stack_trace = traceback.format_exc()
        
        await broadcaster.broadcast({
            "type": "scan_failed",
            "scan_id": scan_id,
            "error": str(e),
            "stack_trace": stack_trace
        })


@app.get("/api/scans")
async def list_scans():
    """List all scans"""
    return {
        "scans": list(active_scans.values())
    }


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Get specific scan details"""
    if scan_id not in active_scans:
        return {"error": "Scan not found"}, 404
    
    return active_scans[scan_id]


@app.get("/api/reports")
async def list_reports():
    """List available reports"""
    reports_dir = Path("reports")
    if not reports_dir.exists():
        return []
    
    reports = []
    for report_file in reports_dir.glob("scan_*.json"):
        try:
            with open(report_file) as f:
                data = json.load(f)
                reports.append({
                    "filename": report_file.name,
                    "scan_id": data.get("scan_id", "unknown"),
                    "timestamp": data.get("timestamp", "unknown"),
                    "target": data.get("target", "unknown"),
                    "size": report_file.stat().st_size,
                    "summary": data.get("summary", {}),
                    "prompt_injection_results": data.get("prompt_injection_results", {}),
                    "pentest_results": data.get("pentest_results", {}),
                    "tools_discovered": data.get("tools_discovered", 0)
                })
        except Exception as e:
            logger.error(f"Error reading report {report_file}: {e}")
    
    return sorted(reports, key=lambda x: x["timestamp"], reverse=True)


@app.get("/api/reports/{filename}")
async def get_report(filename: str):
    """Get specific report"""
    report_path = Path("reports") / filename
    
    if not report_path.exists():
        return {"error": "Report not found"}, 404
    
    with open(report_path) as f:
        return json.load(f)


# WebSocket endpoint removed - using SSE instead


@app.post("/api/discover")
async def discover_server(request: ScanRequest):
    """Discover MCP server capabilities"""
    try:
        client = MCPClient(base_url=request.url)
        await client.connect()
        
        # List tools
        tools_response = await client.list_tools()
        tools = []
        if tools_response.success and tools_response.data:
            tools = tools_response.data.get("tools", [])
        
        # List resources
        resources_response = await client.list_resources()
        resources = []
        if resources_response.success and resources_response.data:
            resources = resources_response.data.get("resources", [])
        
        await client.close()
        
        return {
            "success": True,
            "tools": tools,
            "resources": resources,
            "tool_count": len(tools),
            "resource_count": len(resources)
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


class TestConnectionRequest(BaseModel):
    url: str
    auth_token: Optional[str] = None


@app.post("/api/test-connection")
async def test_connection(request: TestConnectionRequest):
    """Test MCP server connection and list capabilities"""
    try:
        headers = {}
        if request.auth_token:
            headers["Authorization"] = f"Bearer {request.auth_token}"
        
        client = MCPClient(
            base_url=request.url,
            headers=headers if headers else None
        )
        await client.connect()
        
        # Initialize and get server info
        init_response = await client.initialize()
        server_info = {}
        if init_response.success and init_response.data:
            server_info = init_response.data
        
        # List tools
        tools_response = await client.list_tools()
        tools = []
        if tools_response.success and tools_response.data:
            tools = tools_response.data.get("tools", [])
        
        # List resources
        resources_response = await client.list_resources()
        resources = []
        if resources_response.success and resources_response.data:
            resources = resources_response.data.get("resources", [])
        
        await client.close()
        
        return {
            "success": True,
            "server_info": server_info,
            "tools": tools,
            "resources": resources
        }
    
    except Exception as e:
        logger.error(f"Connection test failed: {e}")
        return {
            "success": False,
            "error": str(e)
        }


class ExecuteToolRequest(BaseModel):
    url: str
    auth_token: Optional[str] = None
    tool_name: str
    arguments: Dict[str, Any] = {}


@app.post("/api/execute-tool")
async def execute_tool(request: ExecuteToolRequest):
    """Execute a tool on the MCP server"""
    try:
        headers = {}
        if request.auth_token:
            headers["Authorization"] = f"Bearer {request.auth_token}"
        
        client = MCPClient(
            base_url=request.url,
            headers=headers if headers else None
        )
        await client.connect()
        
        # Initialize
        await client.initialize()
        
        # Call tool
        response = await client.call_tool(request.tool_name, request.arguments)
        
        await client.close()
        
        if response.success:
            return {
                "success": True,
                "result": response.data
            }
        else:
            return {
                "success": False,
                "error": response.error or "Tool execution failed"
            }
    
    except Exception as e:
        logger.error(f"Tool execution failed: {e}")
        return {
            "success": False,
            "error": str(e)
        }


class OAuthProxyRequest(BaseModel):
    """OAuth proxy request model"""
    url: str
    method: str = "GET"
    headers: Optional[Dict[str, str]] = None
    body: Optional[Dict[str, Any]] = None
    form_data: Optional[Dict[str, str]] = None


@app.post("/api/oauth-proxy")
async def oauth_proxy(request: OAuthProxyRequest):
    """
    Proxy OAuth requests to bypass CORS restrictions
    This endpoint forwards requests to OAuth servers from the backend
    """
    try:
        async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
            headers = request.headers or {}
            
            # Ensure proper headers
            if request.form_data:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                # Log form data for debugging token requests
                if 'token' in request.url:
                    logger.info(f"Token request form data keys: {list(request.form_data.keys())}")
                    logger.info(f"Token request has client_secret: {'client_secret' in request.form_data}")
            elif request.body:
                headers['Content-Type'] = 'application/json'
            
            if 'Accept' not in headers:
                headers['Accept'] = 'application/json'
            
            # Make the request
            if request.method.upper() == "GET":
                response = await client.get(request.url, headers=headers)
            elif request.method.upper() == "POST":
                if request.form_data:
                    response = await client.post(
                        request.url,
                        headers=headers,
                        data=request.form_data
                    )
                else:
                    response = await client.post(
                        request.url,
                        headers=headers,
                        json=request.body
                    )
            else:
                return {
                    "success": False,
                    "error": f"Unsupported method: {request.method}"
                }
            
            # Return response
            try:
                response_data = response.json()
            except:
                response_data = response.text
            
            return {
                "success": response.is_success,
                "status": response.status_code,
                "headers": dict(response.headers),
                "data": response_data
            }
            
    except Exception as e:
        logger.error(f"OAuth proxy failed: {e}")
        return {
            "success": False,
            "error": str(e)
        }


if __name__ == "__main__":
    import uvicorn
    
    # Create directories
    Path("reports").mkdir(exist_ok=True)
    Path("logs").mkdir(exist_ok=True)
    
    # Mount static files
    Path("mcp_security/web/static").mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory="mcp_security/web/static"), name="static")
    
    print("\n" + "="*60)
    print("🔒 MCP Security Testing Framework - Web UI")
    print("="*60)
    print(f"\n🌐 Server starting at: http://localhost:8000")
    print(f"📊 Access the dashboard at: http://localhost:8000")
    print(f"📡 Event stream endpoint: http://localhost:8000/api/events")
    print(f"\n⚠️  For authorized security testing only!")
    print("="*60 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
