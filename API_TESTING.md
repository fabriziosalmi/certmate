# CertMate API Testing Suite

This directory contains comprehensive testing tools for CertMate API endpoints. Use these before committing to ensure all endpoints are working correctly.

## Quick Start

### 1. Basic Quick Test (Recommended)
```bash
# Run this before every commit!
./quick_test.sh
```

### 2. Full Test with Manual Token
```bash
python3 test_all_endpoints.py --token YOUR_API_TOKEN
```

### 3. Auto-load Token from Settings
```bash
python3 test_all_endpoints.py --auto-token
```

## Test Scripts

### `quick_test.sh` 
**🚀 Use this for daily development!**

- Checks if server is running
- Automatically loads API token from `data/settings.json`
- Runs all endpoint tests
- Provides clear pass/fail status
- Perfect for pre-commit validation

```bash
./quick_test.sh                    # Test all endpoints
./quick_test.sh --public-only      # Test only public endpoints
```

### `test_all_endpoints.py`
**🔧 Advanced testing with options**

The main testing script with comprehensive options:

```bash
# Basic usage
python3 test_all_endpoints.py

# With custom server URL
python3 test_all_endpoints.py --url http://192.168.1.100:8000

# With manual API token
python3 test_all_endpoints.py --token your-api-bearer-token

# Auto-load token from settings.json
python3 test_all_endpoints.py --auto-token

# Test only public endpoints (no auth needed)
python3 test_all_endpoints.py --public-only

# Quick test of essential endpoints only
python3 test_all_endpoints.py --quick --auto-token
```

## What Gets Tested

### ✅ Health Endpoints (No Auth Required)
- `GET /api/health` - API health check
- `GET /health` - Web health check

### ✅ Settings Endpoints (Auth Required)
- `GET /api/settings` - Get current settings
- `GET /api/settings/dns-providers` - Get DNS providers info
- `POST /api/settings` - Update settings

### ✅ Certificate Endpoints (Auth Required)
- `GET /api/certificates` - List all certificates
- `POST /api/certificates/create` - Create new certificate
- `GET /api/certificates/{domain}/download` - Download certificate
- `POST /api/certificates/{domain}/renew` - Renew certificate

### ✅ Cache Management (Auth Required)
- `GET /api/cache/stats` - Get cache statistics
- `POST /api/cache/clear` - Clear deployment cache

### ✅ Backup & Restore (Auth Required)
- `GET /api/backups` - List all backups
- `POST /api/backups/create` - Create manual backup
- `POST /api/backups/cleanup` - Cleanup old backups

### ✅ Web Interface Endpoints
- `GET /` - Main dashboard
- `GET /settings` - Settings page
- `GET /help` - Help page
- `GET /docs/` - API documentation
- `GET /api/swagger.json` - Swagger specification
- Various `/api/web/*` endpoints

## Expected Results

### 🟢 Success Indicators
- **✅ Green checkmarks** - Endpoint working correctly
- **Status codes 200/201** - Normal success responses
- **Status codes 400/422** - Expected validation errors (normal)
- **Status code 404** - Expected for non-existent resources

### 🔴 Failure Indicators
- **❌ Red X marks** - Endpoint not working
- **Connection refused** - Server not running
- **401 Unauthorized** - Invalid/missing API token
- **500 Internal Server Error** - Application bug

## Integration with Development Workflow

### Pre-Commit Hook (Recommended)
Add this to your Git pre-commit hook:

```bash
#!/bin/sh
echo "Running API endpoint tests..."
./quick_test.sh
if [ $? -ne 0 ]; then
    echo "❌ API tests failed! Commit aborted."
    exit 1
fi
echo "✅ All API tests passed!"
```

### CI/CD Integration
```yaml
# GitHub Actions example
- name: Test API Endpoints
  run: |
    python app.py &
    sleep 5
    python3 test_all_endpoints.py --auto-token
```

### Development Workflow
1. **Start development server**: `python app.py`
2. **Make your changes**
3. **Run quick test**: `./quick_test.sh`
4. **Fix any failing tests**
5. **Commit when all tests pass**: `git commit -m "..."`

## Troubleshooting

### "Server not running" Error
```bash
# Make sure server is started
python app.py
# Or in background: python app.py &
```

### "Could not load API token" Warning
```bash
# Check if settings.json exists
ls data/settings.json

# Or provide token manually
python3 test_all_endpoints.py --token YOUR_TOKEN
```

### Authentication Errors (401)
- Check your API token in `data/settings.json`
- Verify token is correctly formatted
- Ensure token has proper permissions

### Individual Endpoint Failures
- Check server logs for detailed error messages
- Verify required dependencies are installed
- Ensure database/file permissions are correct

## Advanced Usage

### Testing Against Remote Server
```bash
python3 test_all_endpoints.py \
  --url https://your-production-server.com \
  --token your-production-token
```

### Custom Test Scenarios
```bash
# Test only essential endpoints quickly
python3 test_all_endpoints.py --quick --auto-token

# Test without authentication (public endpoints only)
python3 test_all_endpoints.py --public-only

# Test with verbose output (modify script to add --verbose flag)
```

## Exit Codes

- **0** - All tests passed ✅
- **1** - Some tests failed ❌

Perfect for scripting and CI/CD integration!

---

## Example Output

```
🚀 CertMate API Endpoint Test Suite
Testing API at: http://127.0.0.1:8000
Timestamp: 2025-01-07 10:30:15
================================================================================

🏥 Health Check Endpoints
  ✅ GET  /api/health                      API Health Check               ✓ 200
  ✅ GET  /health                          Web Health Check               ✓ 200

⚙️  Settings Endpoints
  ✅ GET  /api/settings                    Get Current Settings           ✓ 200
  ✅ GET  /api/settings/dns-providers      Get DNS Providers              ✓ 200
  ✅ POST /api/settings                    Update Settings                ✓ 200

🔒 Certificate Endpoints
  ✅ GET  /api/certificates                List All Certificates          ✓ 200
  ✅ POST /api/certificates/create         Create Certificate             ✓ 400
  ✅ GET  /api/certificates/test.../download Download Certificate         ✓ 404
  ✅ POST /api/certificates/test.../renew  Renew Certificate              ✓ 404

================================================================================
📊 Test Summary
Total Tests: 24
✅ Passed: 24
❌ Failed: 0

🎉 All tests passed! Ready to commit.
```

This testing suite will give you confidence that your API is working correctly before every commit! 🚀
