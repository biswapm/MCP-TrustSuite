# Deploying MCP-TrustSuite to Azure App Services

This guide explains how to deploy MCP-TrustSuite as a web service on Azure App Services.

## Prerequisites

- Azure account with active subscription
- Azure CLI installed locally
- Git installed locally
- Python 3.11+ installed locally

## Deployment Methods

### Method 1: Azure CLI Deployment (Recommended)

#### 1. Install Azure CLI
```bash
# Download from: https://aka.ms/installazurecliwindows
# Or use PowerShell:
winget install -e --id Microsoft.AzureCLI
```

#### 2. Login to Azure
```bash
az login
```

#### 3. Create Resource Group
```bash
az group create \
  --name mcp-trustsuite-rg \
  --location eastus
```

#### 4. Create App Service Plan
```bash
# Free tier (F1) - for testing
az appservice plan create \
  --name mcp-trustsuite-plan \
  --resource-group mcp-trustsuite-rg \
  --sku F1 \
  --is-linux

# Or Basic tier (B1) - for production
az appservice plan create \
  --name mcp-trustsuite-plan \
  --resource-group mcp-trustsuite-rg \
  --sku B1 \
  --is-linux
```

#### 5. Create Web App
```bash
az webapp create \
  --resource-group mcp-trustsuite-rg \
  --plan mcp-trustsuite-plan \
  --name mcp-trustsuite \
  --runtime "PYTHON:3.11"
```

#### 6. Configure App Settings
```bash
# Set Python version
az webapp config appsettings set \
  --resource-group mcp-trustsuite-rg \
  --name mcp-trustsuite \
  --settings WEBSITE_RUN_FROM_PACKAGE="1"

# Set startup command
az webapp config set \
  --resource-group mcp-trustsuite-rg \
  --name mcp-trustsuite \
  --startup-file "startup.sh"
```

#### 7. Deploy from GitHub
```bash
# Configure deployment from GitHub
az webapp deployment source config \
  --name mcp-trustsuite \
  --resource-group mcp-trustsuite-rg \
  --repo-url https://github.com/biswapm/MCP-TrustSuite.git \
  --branch main \
  --manual-integration
```

#### 8. Stream Logs (Optional)
```bash
az webapp log tail \
  --name mcp-trustsuite \
  --resource-group mcp-trustsuite-rg
```

### Method 2: Azure Portal Deployment

#### 1. Login to Azure Portal
Navigate to https://portal.azure.com

#### 2. Create Web App
- Click **"Create a resource"**
- Search for **"Web App"**
- Click **"Create"**

#### 3. Configure Basics
- **Subscription**: Select your subscription
- **Resource Group**: Create new: `mcp-trustsuite-rg`
- **Name**: `mcp-trustsuite` (must be globally unique)
- **Publish**: Code
- **Runtime stack**: Python 3.11
- **Operating System**: Linux
- **Region**: East US (or your preferred region)
- **Pricing plan**: Free F1 or Basic B1

#### 4. Configure Deployment
- Go to **Deployment Center**
- **Source**: GitHub
- **Organization**: biswapm
- **Repository**: MCP-TrustSuite
- **Branch**: main
- Click **Save**

#### 5. Configure Application Settings
- Go to **Configuration** → **Application settings**
- Add the following settings:
  - `SCM_DO_BUILD_DURING_DEPLOYMENT` = `true`
  - `WEBSITE_RUN_FROM_PACKAGE` = `1`
- Go to **General settings**
- **Startup Command**: `startup.sh`
- Click **Save**

#### 6. Access Your Application
- URL: `https://mcp-trustsuite.azurewebsites.net`

### Method 3: Local Git Deployment

#### 1. Configure Local Git
```bash
az webapp deployment source config-local-git \
  --name mcp-trustsuite \
  --resource-group mcp-trustsuite-rg
```

#### 2. Get Deployment Credentials
```bash
az webapp deployment list-publishing-credentials \
  --name mcp-trustsuite \
  --resource-group mcp-trustsuite-rg \
  --query "{Username:publishingUserName, Password:publishingPassword}"
```

#### 3. Add Azure Remote
```bash
git remote add azure https://<username>@mcp-trustsuite.scm.azurewebsites.net/mcp-trustsuite.git
```

#### 4. Deploy
```bash
git push azure main
```

### Method 4: VS Code Deployment

#### 1. Install Azure App Service Extension
- Open VS Code
- Go to Extensions (Ctrl+Shift+X)
- Search for "Azure App Service"
- Install the extension

#### 2. Sign in to Azure
- Click Azure icon in sidebar
- Click **"Sign in to Azure"**

#### 3. Deploy
- Right-click on your project folder
- Select **"Deploy to Web App"**
- Choose subscription and create/select app service
- Confirm deployment

## Configuration

### Environment Variables

Set these in Azure Portal under **Configuration** → **Application settings**:

```
# Optional: Custom port (default: 8000)
PORT=8000

# Optional: Log level
LOG_LEVEL=INFO

# Optional: Enable debug mode (dev only)
DEBUG=false
```

### Custom Domain (Optional)

#### 1. Add Custom Domain
```bash
az webapp config hostname add \
  --webapp-name mcp-trustsuite \
  --resource-group mcp-trustsuite-rg \
  --hostname www.yourdomain.com
```

#### 2. Configure SSL
```bash
az webapp config ssl bind \
  --name mcp-trustsuite \
  --resource-group mcp-trustsuite-rg \
  --certificate-thumbprint <thumbprint> \
  --ssl-type SNI
```

## Monitoring and Troubleshooting

### View Application Logs
```bash
# Stream logs
az webapp log tail \
  --name mcp-trustsuite \
  --resource-group mcp-trustsuite-rg

# Download logs
az webapp log download \
  --name mcp-trustsuite \
  --resource-group mcp-trustsuite-rg \
  --log-file logs.zip
```

### Enable Application Insights
```bash
az monitor app-insights component create \
  --app mcp-trustsuite-insights \
  --location eastus \
  --resource-group mcp-trustsuite-rg \
  --application-type web

# Get instrumentation key
az monitor app-insights component show \
  --app mcp-trustsuite-insights \
  --resource-group mcp-trustsuite-rg \
  --query instrumentationKey
```

### Common Issues

#### Issue: App not starting
**Solution**: Check startup logs
```bash
az webapp log tail --name mcp-trustsuite --resource-group mcp-trustsuite-rg
```

#### Issue: Dependencies not installed
**Solution**: Ensure `requirements.txt` is in root directory and contains all dependencies

#### Issue: Port binding error
**Solution**: Make sure your app binds to `0.0.0.0` and uses the `PORT` environment variable

#### Issue: Python version mismatch
**Solution**: Update `runtime.txt` to specify Python version:
```
python-3.11
```

## Scaling

### Manual Scaling
```bash
# Scale up (change pricing tier)
az appservice plan update \
  --name mcp-trustsuite-plan \
  --resource-group mcp-trustsuite-rg \
  --sku B2

# Scale out (add instances)
az appservice plan update \
  --name mcp-trustsuite-plan \
  --resource-group mcp-trustsuite-rg \
  --number-of-workers 3
```

### Auto-scaling
```bash
# Enable autoscale
az monitor autoscale create \
  --resource-group mcp-trustsuite-rg \
  --resource mcp-trustsuite-plan \
  --resource-type Microsoft.Web/serverfarms \
  --name autoscale-rules \
  --min-count 1 \
  --max-count 5 \
  --count 2
```

## Cost Optimization

### Pricing Tiers
- **Free (F1)**: Free, 1 GB RAM, 60 CPU minutes/day
- **Basic (B1)**: ~$13/month, 1.75 GB RAM, unlimited
- **Standard (S1)**: ~$69/month, 1.75 GB RAM, auto-scale
- **Premium (P1v2)**: ~$146/month, 3.5 GB RAM, advanced features

### Tips
1. Start with Free tier for testing
2. Use Basic tier for low-traffic production
3. Enable auto-scale only if needed
4. Set up alerts for cost monitoring

## Security Best Practices

### 1. Enable HTTPS Only
```bash
az webapp update \
  --name mcp-trustsuite \
  --resource-group mcp-trustsuite-rg \
  --https-only true
```

### 2. Configure Authentication (Optional)
```bash
az webapp auth update \
  --name mcp-trustsuite \
  --resource-group mcp-trustsuite-rg \
  --enabled true \
  --action LoginWithAzureActiveDirectory
```

### 3. Set IP Restrictions
```bash
az webapp config access-restriction add \
  --name mcp-trustsuite \
  --resource-group mcp-trustsuite-rg \
  --rule-name "Allow-Office-IP" \
  --action Allow \
  --ip-address 203.0.113.0/24 \
  --priority 100
```

### 4. Enable Managed Identity
```bash
az webapp identity assign \
  --name mcp-trustsuite \
  --resource-group mcp-trustsuite-rg
```

## Backup and Disaster Recovery

### Configure Backup
```bash
az webapp config backup create \
  --resource-group mcp-trustsuite-rg \
  --webapp-name mcp-trustsuite \
  --backup-name daily-backup \
  --container-url "<storage-sas-url>" \
  --frequency 1d \
  --retain-one true
```

## Cleanup

### Delete Resources
```bash
# Delete entire resource group
az group delete \
  --name mcp-trustsuite-rg \
  --yes --no-wait
```

## Additional Resources

- [Azure App Service Documentation](https://docs.microsoft.com/en-us/azure/app-service/)
- [Python on Azure](https://docs.microsoft.com/en-us/azure/developer/python/)
- [Azure CLI Reference](https://docs.microsoft.com/en-us/cli/azure/)
- [Pricing Calculator](https://azure.microsoft.com/en-us/pricing/calculator/)

## Support

For deployment issues:
1. Check Azure Portal logs
2. Review startup.sh and startup.py
3. Verify requirements.txt dependencies
4. Open issue on GitHub: https://github.com/biswapm/MCP-TrustSuite/issues
