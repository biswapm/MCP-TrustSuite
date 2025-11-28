# MCP Security Testing Framework - Web UI

## 🌐 Web Interface

The framework now includes a beautiful, real-time web interface for easier security testing!

### Starting the Web UI

```bash
# Start the web server
python -m mcp_security.web_ui

# Or using uvicorn directly
uvicorn mcp_security.web_ui:app --host 0.0.0.0 --port 8000
```

Then open your browser to: **http://localhost:8000**

### Features

#### 🎯 Scanner Tab
- **New Scan Form**: Configure and launch security scans
  - Full Security Scan
  - Quick Scan
  - Prompt Injection Test
  - Penetration Test
- **Real-time Progress**: Watch scans progress with live updates
- **Active Scans**: View all currently running scans

#### 📊 Reports Tab
- Browse all generated reports
- View detailed scan results
- Interactive risk level visualization
- JSON report viewer

#### 🔍 Discover Tab
- Discover MCP server capabilities
- View available tools and resources
- Quick server reconnaissance

#### 📋 Console Tab
- Real-time log streaming
- Color-coded messages
- WebSocket connection status

### API Endpoints

The web UI exposes a RESTful API:

#### Health Check
```bash
GET /api/health
```

#### Start a Scan
```bash
POST /api/scan
{
  "url": "http://localhost:3000",
  "scan_type": "full",  # full, quick, injection, pentest
  "timeout": 30,
  "verify_ssl": true
}
```

#### List Scans
```bash
GET /api/scans
```

#### Get Scan Details
```bash
GET /api/scans/{scan_id}
```

#### List Reports
```bash
GET /api/reports
```

#### Get Report
```bash
GET /api/reports/{filename}
```

#### Discover Server
```bash
POST /api/discover
{
  "url": "http://localhost:3000"
}
```

#### WebSocket
```
WS /ws
```
Real-time updates for:
- Scan started
- Scan progress
- Scan completed
- Scan failed

### Using with CLI

You can still use the command-line interface:

```bash
# CLI scan
python -m mcp_security scan --url http://localhost:3000

# Web UI
python -m mcp_security.web_ui
```

### Screenshots

The web interface includes:
- 🎨 Modern, responsive design
- 📱 Mobile-friendly layout
- 🔄 Real-time updates via WebSocket
- 📈 Progress bars and status indicators
- 🎯 Risk level badges (Critical/High/Medium/Low)
- 📊 Statistics dashboard
- 🌓 Professional color scheme

### Security Considerations

⚠️ **Important Security Notes:**

1. **Authorization Required**: Always obtain proper authorization before testing
2. **Network Access**: The web server binds to 0.0.0.0 (all interfaces)
3. **Production Use**: Add authentication/authorization for production
4. **SSL/TLS**: Consider using HTTPS in production environments
5. **Firewall**: Configure firewall rules appropriately

### Customization

#### Change Port
```bash
uvicorn mcp_security.web_ui:app --port 8080
```

#### Enable SSL
```bash
uvicorn mcp_security.web_ui:app --ssl-keyfile key.pem --ssl-certfile cert.pem
```

#### Custom Host
```bash
uvicorn mcp_security.web_ui:app --host 127.0.0.1
```

### Development

To modify the UI:
1. Edit `mcp_security/web/index.html` for frontend
2. Edit `mcp_security/web_ui.py` for backend
3. Refresh browser to see changes

### Troubleshooting

**WebSocket not connecting:**
- Check firewall settings
- Verify server is running
- Check browser console for errors

**Scans not showing:**
- Verify target URL is accessible
- Check server logs
- Ensure MCP server is running

**Reports not loading:**
- Check `reports/` directory exists
- Verify file permissions
- Check console for errors

### Browser Compatibility

Tested on:
- ✅ Chrome/Edge (latest)
- ✅ Firefox (latest)
- ✅ Safari (latest)

### Contributing

To add new features to the web UI:
1. Update `web_ui.py` for backend functionality
2. Update `index.html` for frontend UI
3. Add WebSocket message handlers
4. Update documentation

---

**Enjoy the new web interface!** 🎉
