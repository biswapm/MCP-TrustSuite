# 🎉 MCP Security Testing Framework - Complete with Web UI!

## ✅ What's New: Beautiful Web Interface

Your MCP Security Testing Framework now includes a **stunning web-based UI** with real-time reporting!

### 🚀 Three Easy Ways to Use

#### 1️⃣ Interactive Launcher (Easiest)
```bash
# Windows - Double click or run:
launch.bat

# Linux/Mac:
chmod +x launch.sh
./launch.sh

# Or with Python:
python launch.py
```

**You'll see an interactive menu:**
```
╔═══════════════════════════════════════════════════════════════════╗
║   🔒 MCP Security Testing Framework                              ║
╚═══════════════════════════════════════════════════════════════════╝

Choose an option:
  1. 🌐 Launch Web UI (Recommended)
  2. 💻 Use CLI - Full Scan
  3. 💻 Use CLI - Quick Scan
  4. 💻 Use CLI - Prompt Injection Test
  5. 💻 Use CLI - Penetration Test
  6. 🔍 Use CLI - Discover Server
  7. 📚 View Documentation
  8. ❌ Exit
```

#### 2️⃣ Web UI Directly
```bash
python -m mcp_security.web_ui
```
**Opens at:** http://localhost:8000

#### 3️⃣ Command Line (Original)
```bash
python -m mcp_security scan --url http://localhost:3000
```

---

## 🌐 Web Interface Features

### 📱 Modern Dashboard
- **Beautiful Design**: Purple gradient theme with smooth animations
- **Responsive**: Works on desktop, tablet, and mobile
- **Real-time**: WebSocket updates for live progress
- **Interactive**: Click, configure, and scan with ease

### 🎯 Scanner Tab
- Configure scan settings with dropdown menus
- Choose from 4 scan types:
  - ✅ Full Security Scan
  - ⚡ Quick Scan
  - 💉 Prompt Injection Test
  - 🛡️ Penetration Test
- **Real-time progress bars** showing scan status
- Live feed of active scans

### 📊 Reports Tab
- Browse all generated reports
- **Visual statistics dashboard**:
  - Total vulnerabilities count
  - Critical/High severity counts
  - Risk level badges (color-coded)
  - Security scores
- One-click report viewing
- JSON report explorer

### 🔍 Discover Tab
- Quick server reconnaissance
- View available tools and resources
- Display tool descriptions
- Statistics dashboard

### 📋 Console Tab
- **Live log streaming** with color coding:
  - 🔵 Info (blue)
  - 🟡 Warning (yellow)
  - 🔴 Error (red)
  - 🟢 Success (green)
- WebSocket connection status indicator
- Auto-scrolling console

---

## 🎨 UI Screenshots Description

### Main Dashboard
```
╔════════════════════════════════════════════════════════╗
║  🔒 MCP Security Testing Framework                    ║
║  Comprehensive security testing for MCP servers       ║
╚════════════════════════════════════════════════════════╝

[Scanner] [Reports] [Discover] [Console]     ● Connected

┌─────────────────────────┬──────────────────────────┐
│  🎯 New Scan           │  📊 Active Scans        │
│                        │                          │
│  Target URL:           │  [20251120_143022]      │
│  [http://localhost:300]│  Status: Running         │
│                        │  Progress: 45%           │
│  Scan Type:            │  ──────────────         │
│  [Full Security Scan▼] │                          │
│                        │  [20251120_142315]      │
│  ☑ Verify SSL          │  Status: Completed      │
│                        │  Progress: 100%          │
│  [Start Scan] [Discover]│                         │
└─────────────────────────┴──────────────────────────┘

Progress: ██████████░░░░░░░░░░ 45%
Message: Running prompt injection tests...
```

### Reports View
```
┌───────────────────────────────────────────────────────┐
│  📄 Scan Reports                                      │
│                                                       │
│  ┌─────────────────────────────────────────────────┐ │
│  │  Scan: 20251120_143022                          │ │
│  │  Target: http://localhost:3000                  │ │
│  │  Time: 11/20/2025, 2:30:22 PM                  │ │
│  │  Size: 15.47 KB                                 │ │
│  │  [View Report]                                  │ │
│  └─────────────────────────────────────────────────┘ │
│                                                       │
│  ┌───┬───────┬─────────┬──────┐                     │
│  │ 5 │   2   │   HIGH  │      │                     │
│  │Total Critical │   Risk  │      │                     │
│  └───┴───────┴─────────┴──────┘                     │
└───────────────────────────────────────────────────────┘
```

---

## 🔧 Installation & Setup

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

**New dependencies for Web UI:**
- `fastapi` - Web framework
- `uvicorn` - ASGI server
- `websockets` - Real-time updates

### Step 2: Launch
```bash
# Method 1: Interactive launcher
python launch.py

# Method 2: Direct web UI
python -m mcp_security.web_ui

# Method 3: CLI (original)
python -m mcp_security scan --url YOUR_URL
```

### Step 3: Open Browser
Navigate to: **http://localhost:8000**

---

## 📖 Complete Documentation

| File | Description |
|------|-------------|
| **README.md** | Main documentation |
| **WEB_UI.md** | Web interface guide |
| **QUICKSTART.md** | Quick start guide |
| **PROJECT_OVERVIEW.md** | Technical details |
| **CONTRIBUTING.md** | Development guide |

---

## 🎯 Quick Examples

### Example 1: Web UI Scan
1. Open http://localhost:8000
2. Enter target URL: `http://localhost:3000`
3. Select "Full Security Scan"
4. Click "Start Scan"
5. Watch real-time progress
6. View report when complete

### Example 2: CLI Quick Scan
```bash
python -m mcp_security scan --url http://localhost:3000 --quick -o reports/my_scan.json
```

### Example 3: Prompt Injection via API
```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://localhost:3000",
    "scan_type": "injection",
    "tool_name": "search",
    "parameter_name": "query"
  }'
```

---

## 🔌 API Endpoints

The Web UI exposes a full REST API:

```
GET  /                         - Web UI
GET  /api/health              - Health check
POST /api/scan                - Start scan
GET  /api/scans               - List all scans
GET  /api/scans/{id}          - Get scan details
GET  /api/reports             - List reports
GET  /api/reports/{filename}  - Get report
POST /api/discover            - Discover server
WS   /ws                      - WebSocket for real-time updates
```

---

## 🎨 UI Design Highlights

### Colors & Theme
- **Primary**: Purple gradient (#667eea → #764ba2)
- **Success**: Green (#28a745)
- **Warning**: Yellow (#ffc107)
- **Danger**: Red (#dc3545)
- **Dark Console**: #1e1e1e (VS Code style)

### Risk Level Colors
- 🔴 **CRITICAL**: Red badge
- 🟠 **HIGH**: Orange badge
- 🟡 **MEDIUM**: Yellow badge
- 🟢 **LOW**: Green badge
- 🔵 **MINIMAL**: Teal badge

### Interactive Elements
- Smooth hover effects
- Animated progress bars
- Real-time status updates
- Color-coded logs
- Responsive cards
- Tab navigation

---

## ⚠️ Security Notice

**CRITICAL:** This tool is for authorized security testing only!

✅ **DO:**
- Get proper authorization
- Test your own systems
- Follow responsible disclosure
- Use for defensive security

❌ **DON'T:**
- Test without permission
- Use for malicious purposes
- Violate terms of service
- Access unauthorized systems

---

## 🚀 What You Can Do Now

### 1. Test Your MCP Server
```bash
python launch.py
# Choose option 1 for Web UI
```

### 2. Run a Quick Security Check
```bash
python -m mcp_security scan --url YOUR_MCP_SERVER --quick
```

### 3. Explore the Web Interface
- Start the web UI
- Try the discovery tool
- Run a test scan
- View the reports

### 4. Integrate with Your Workflow
- Use the REST API
- Embed in CI/CD pipelines
- Automate security testing
- Generate compliance reports

---

## 🎓 Learning Resources

### For Beginners
1. Read **QUICKSTART.md**
2. Launch the interactive launcher
3. Try the Web UI
4. Run a quick scan

### For Advanced Users
1. Read **WEB_UI.md** for API details
2. Use **PROJECT_OVERVIEW.md** for architecture
3. Check **CONTRIBUTING.md** to extend
4. Integrate with your tools

---

## 📦 Project Structure

```
MCP-Security/
├── launch.py              ← 🎯 Interactive launcher
├── launch.bat             ← Windows launcher
├── launch.sh              ← Linux/Mac launcher
├── mcp_security/
│   ├── web_ui.py          ← 🌐 Web server (NEW!)
│   ├── web/
│   │   └── index.html     ← 🎨 Web interface (NEW!)
│   ├── client/            ← MCP client
│   ├── attacks/           ← Attack modules
│   ├── scanner/           ← Security scanner
│   └── cli.py             ← CLI interface
├── README.md              ← Updated with Web UI info
├── WEB_UI.md              ← Web UI documentation (NEW!)
└── requirements.txt       ← Updated dependencies
```

---

## 🎉 Summary

You now have a **complete security testing framework** with:

✅ Beautiful web interface with real-time updates
✅ Interactive launcher for easy access
✅ Full CLI for automation
✅ RESTful API for integration
✅ WebSocket for live progress
✅ Comprehensive reporting
✅ 14+ prompt injection vectors
✅ 10+ penetration tests
✅ Complete documentation

**Get started in seconds:**
```bash
python launch.py
```

Choose option 1 for the Web UI, and you're ready to test! 🚀

---

**Built for the security community. Test responsibly. Stay ethical.** 🔒
