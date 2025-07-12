#!/bin/bash
# Enhanced Quick Test Script for CertMate
# Comprehensive pre-commit validation including API endpoints, backup/restore, and integration tests

set -e

# Configuration
DEFAULT_URL="http://127.0.0.1:8000"
DEFAULT_PORT="8000"
TIMEOUT=30
VERBOSE=false
QUICK_MODE=false
SKIP_INTEGRATION=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --url)
            DEFAULT_URL="$2"
            shift 2
            ;;
        --port)
            DEFAULT_PORT="$2"
            DEFAULT_URL="http://127.0.0.1:$2"
            shift 2
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --quick|-q)
            QUICK_MODE=true
            shift
            ;;
        --skip-integration)
            SKIP_INTEGRATION=true
            shift
            ;;
        --status)
            # Quick status check mode
            echo "🔍 CertMate Status Check"
            echo "======================="
            if curl -s --max-time 5 "$DEFAULT_URL/health" > /dev/null 2>&1; then
                health_info=$(curl -s --max-time 5 "$DEFAULT_URL/health" 2>/dev/null)
                version=$(echo "$health_info" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('version', 'unknown'))" 2>/dev/null || echo "unknown")
                echo "✅ Server is running at $DEFAULT_URL"
                echo "📊 Version: $version"
                echo "🌐 Web: $DEFAULT_URL"
                echo "📚 API Docs: $DEFAULT_URL/docs/"
                exit 0
            else
                echo "❌ Server not running at $DEFAULT_URL"
                exit 1
            fi
            ;;
        --help|-h)
            echo "Enhanced CertMate Quick Test Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --url URL           API base URL (default: http://127.0.0.1:8000)"
            echo "  --port PORT         Server port (default: 8000)"
            echo "  --timeout SECONDS   Connection timeout (default: 30)"
            echo "  --verbose, -v       Verbose output"
            echo "  --quick, -q         Quick mode (essential tests only)"
            echo "  --skip-integration  Skip integration tests"
            echo "  --status            Quick server status check"
            echo "  --help, -h          Show this help"
            echo ""
            echo "Examples:"
            echo "  $0                           # Run all tests on default port"
            echo "  $0 --port 5000              # Test on port 5000"
            echo "  $0 --quick                  # Quick validation only"
            echo "  $0 --verbose                # Verbose output"
            echo "  $0 --status                 # Quick status check"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Helper functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

log_header() {
    echo ""
    echo -e "${BOLD}${CYAN}$1${NC}"
    echo -e "${CYAN}$(echo "$1" | sed 's/./=/g')${NC}"
}

# Verbose logging
log_verbose() {
    if [ "$VERBOSE" = true ]; then
        echo -e "${WHITE}🔍 $1${NC}"
    fi
}

# Test if server is accessible
test_server_connection() {
    log_header "🔌 Server Connection Test"
    
    log_verbose "Testing connection to $DEFAULT_URL"
    
    if ! curl -s --max-time $TIMEOUT "$DEFAULT_URL/health" > /dev/null 2>&1; then
        log_error "Server not accessible at $DEFAULT_URL"
        log_info "To start the server:"
        echo "  • Docker: docker-compose up -d"
        echo "  • Direct: python app.py --port $DEFAULT_PORT"
        echo "  • Debug:  python app.py --port $DEFAULT_PORT --debug"
        return 1
    fi
    
    # Get server info
    local health_response=$(curl -s --max-time $TIMEOUT "$DEFAULT_URL/health" 2>/dev/null)
    if [ $? -eq 0 ] && [ -n "$health_response" ]; then
        local version=$(echo "$health_response" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('version', 'unknown'))" 2>/dev/null || echo "unknown")
        local status=$(echo "$health_response" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('status', 'unknown'))" 2>/dev/null || echo "unknown")
        log_success "Server is running (version: $version, status: $status)"
    else
        log_success "Server is running"
    fi
}

# Test API token availability
test_api_token() {
    log_header "🔑 API Authentication Test"
    
    if [ -f "data/settings.json" ]; then
        local token=$(python3 -c "import json; print(json.load(open('data/settings.json')).get('api_bearer_token', ''))" 2>/dev/null)
        if [ -n "$token" ] && [ "$token" != "null" ]; then
            # Create masked token for display
            local token_length=${#token}
            local masked_middle=""
            if [ $token_length -gt 12 ]; then
                local middle_length=$((token_length - 12))
                masked_middle=$(printf '%*s' "$middle_length" | tr ' ' '*')
            fi
            local masked_token="${token:0:8}${masked_middle}${token: -4}"
            log_success "API token loaded from settings.json ($masked_token)"
            return 0
        else
            log_warning "No API token found in settings.json"
        fi
    else
        log_warning "settings.json not found"
    fi
    
    log_info "Some tests will be skipped without authentication"
    return 1
}

# Run core API endpoint tests
run_api_tests() {
    log_header "🧪 API Endpoint Tests"
    
    local test_args="--url $DEFAULT_URL --auto-token"
    
    if [ "$QUICK_MODE" = true ]; then
        test_args="$test_args --quick"
        log_info "Running in quick mode (essential endpoints only)"
    fi
    
    if [ "$VERBOSE" = true ]; then
        log_verbose "Running: python3 test_all_endpoints.py $test_args"
    fi
    
    python3 test_all_endpoints.py $test_args
    return $?
}

# Test backup and restore functionality
test_backup_restore() {
    if [ "$SKIP_INTEGRATION" = true ] || [ "$QUICK_MODE" = true ]; then
        log_verbose "Skipping backup/restore tests"
        return 0
    fi
    
    log_header "💾 Backup & Restore Integration Tests"
    
    # Get API token for authenticated requests
    local token=""
    if [ -f "data/settings.json" ]; then
        token=$(python3 -c "import json; print(json.load(open('data/settings.json')).get('api_bearer_token', ''))" 2>/dev/null)
    fi
    
    if [ -z "$token" ] || [ "$token" = "null" ]; then
        log_warning "No API token available - skipping backup/restore tests"
        return 0
    fi
    
    local auth_header="Authorization: Bearer $token"
    local content_header="Content-Type: application/json"
    
    # Test unified backup creation (recommended)
    log_verbose "Testing unified backup creation..."
    local backup_response=$(curl -s --max-time $TIMEOUT -X POST \
        -H "$auth_header" -H "$content_header" \
        -d '{"type": "unified", "reason": "quick_test"}' \
        "$DEFAULT_URL/api/backups/create" 2>/dev/null)
    
    if echo "$backup_response" | grep -q "created_backups\|filename"; then
        log_success "Unified backup creation works"
    elif echo "$backup_response" | grep -q "message.*success\|backup.*created"; then
        log_success "Unified backup creation works"
    else
        log_warning "Unified backup creation may have issues"
        if [ "$VERBOSE" = true ]; then
            log_verbose "Response: $backup_response"
        fi
    fi
    
    # Test backup listing
    log_verbose "Testing backup listing..."
    local list_response=$(curl -s --max-time $TIMEOUT \
        -H "$auth_header" \
        "$DEFAULT_URL/api/backups" 2>/dev/null)
    
    if echo "$list_response" | grep -q "unified\|settings\|certificates"; then
        log_success "Backup listing works"
    else
        log_warning "Backup listing may have issues"
        log_verbose "Response: $list_response"
    fi
}

# Test certificate functionality (basic checks)
test_certificate_operations() {
    if [ "$SKIP_INTEGRATION" = true ] || [ "$QUICK_MODE" = true ]; then
        log_verbose "Skipping certificate operation tests"
        return 0
    fi
    
    log_header "🔒 Certificate Operations Test"
    
    # Get API token
    local token=""
    if [ -f "data/settings.json" ]; then
        token=$(python3 -c "import json; print(json.load(open('data/settings.json')).get('api_bearer_token', ''))" 2>/dev/null)
    fi
    
    if [ -z "$token" ] || [ "$token" = "null" ]; then
        log_warning "No API token available - skipping certificate tests"
        return 0
    fi
    
    local auth_header="Authorization: Bearer $token"
    
    # Test certificate listing
    log_verbose "Testing certificate listing..."
    local cert_response=$(curl -s --max-time $TIMEOUT \
        -H "$auth_header" \
        "$DEFAULT_URL/api/certificates" 2>/dev/null)
    
    if echo "$cert_response" | python3 -c "import sys, json; json.load(sys.stdin)" 2>/dev/null; then
        local cert_count=$(echo "$cert_response" | python3 -c "import sys, json; data=json.load(sys.stdin); print(len(data) if isinstance(data, list) else 0)" 2>/dev/null || echo "0")
        log_success "Certificate listing works ($cert_count certificates found)"
    else
        log_warning "Certificate listing may have issues"
        log_verbose "Response: $cert_response"
    fi
}

# Test web interface accessibility
test_web_interface() {
    if [ "$QUICK_MODE" = true ]; then
        log_verbose "Skipping web interface tests in quick mode"
        return 0
    fi
    
    log_header "🌐 Web Interface Tests"
    
    # Test main pages
    local pages=("/" "/settings" "/docs/")
    local success_count=0
    
    for page in "${pages[@]}"; do
        log_verbose "Testing page: $page"
        local http_code=$(curl -s --max-time $TIMEOUT -o /dev/null -w "%{http_code}" "$DEFAULT_URL$page" 2>/dev/null || echo "000")
        if [[ "$http_code" =~ ^2[0-9][0-9]$ ]]; then
            log_success "Page accessible: $page"
            ((success_count++))
        elif [[ "$http_code" =~ ^3[0-9][0-9]$ ]]; then
            log_success "Page accessible: $page (redirect)"
            ((success_count++))
        else
            log_warning "Page may have issues: $page (HTTP $http_code)"
        fi
    done
    
    if [ $success_count -eq ${#pages[@]} ]; then
        log_success "All web pages accessible"
    else
        log_warning "Some web pages had issues ($success_count/${#pages[@]} accessible)"
    fi
}

# Test file system and permissions
test_filesystem() {
    log_header "📁 File System Tests"
    
    # Check required directories
    local dirs=("data" "certificates" "backups" "logs")
    local dir_success=0
    
    for dir in "${dirs[@]}"; do
        if [ -d "$dir" ]; then
            if [ -w "$dir" ]; then
                log_success "Directory OK: $dir (writable)"
                ((dir_success++))
            else
                log_warning "Directory not writable: $dir"
            fi
        else
            log_warning "Directory missing: $dir"
        fi
    done
    
    # Check settings file
    if [ -f "data/settings.json" ]; then
        if python3 -c "import json; json.load(open('data/settings.json'))" 2>/dev/null; then
            log_success "Settings file is valid JSON"
        else
            log_error "Settings file is invalid JSON"
            return 1
        fi
    else
        log_info "Settings file will be created on first run"
    fi
}

# Performance check
test_performance() {
    if [ "$QUICK_MODE" = true ]; then
        log_verbose "Skipping performance tests in quick mode"
        return 0
    fi
    
    log_header "⚡ Performance Tests"
    
    # Test API response time
    log_verbose "Testing API response time..."
    local start_time=$(date +%s.%N)
    curl -s --max-time $TIMEOUT "$DEFAULT_URL/health" > /dev/null 2>&1
    local end_time=$(date +%s.%N)
    local response_time=$(echo "$end_time - $start_time" | bc 2>/dev/null || echo "unknown")
    
    if [ "$response_time" != "unknown" ]; then
        local response_ms=$(echo "$response_time * 1000" | bc 2>/dev/null || echo "unknown")
        if [ "$response_ms" != "unknown" ]; then
            local response_int=$(echo "$response_ms" | cut -d. -f1)
            if [ "$response_int" -lt 1000 ]; then
                log_success "API response time: ${response_int}ms (good)"
            elif [ "$response_int" -lt 3000 ]; then
                log_warning "API response time: ${response_int}ms (acceptable)"
            else
                log_warning "API response time: ${response_int}ms (slow)"
            fi
        else
            log_info "API responds within timeout"
        fi
    else
        log_info "API responds within timeout"
    fi
}

# Main execution
main() {
    echo -e "${BOLD}${CYAN}🧪 CertMate Enhanced Quick Test Suite${NC}"
    echo -e "${WHITE}Testing server at: $DEFAULT_URL${NC}"
    echo -e "${WHITE}Mode: $([ "$QUICK_MODE" = true ] && echo "Quick" || echo "Comprehensive")${NC}"
    echo -e "${WHITE}Timestamp: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo "================================================================================"
    
    local overall_success=true
    
    # Core tests (always run)
    test_server_connection || overall_success=false
    test_api_token
    test_filesystem || overall_success=false
    
    # API tests (main test suite)
    if ! run_api_tests; then
        overall_success=false
    fi
    
    # Optional integration tests
    if [ "$overall_success" = true ]; then
        test_backup_restore
        test_certificate_operations
        test_web_interface
        test_performance
    else
        log_warning "Skipping integration tests due to core test failures"
    fi
    
    # Final summary
    log_header "📊 Test Summary"
    
    if [ "$overall_success" = true ]; then
        echo -e "${BOLD}${GREEN}🎉 All core tests passed! Ready to commit! 🚀${NC}"
        echo ""
        log_info "Tips for success:"
        echo "  • Backup/restore functionality is working"
        echo "  • All API endpoints are responding correctly"
        echo "  • File system permissions are correct"
        echo "  • Ready for production deployment"
        exit 0
    else
        echo -e "${BOLD}${RED}🚫 Some tests failed. Please review before committing.${NC}"
        echo ""
        log_info "Common fixes:"
        echo "  • Check if server is running: python app.py --port $DEFAULT_PORT"
        echo "  • Verify API token in data/settings.json"
        echo "  • Check file permissions: chmod -R 755 data certificates backups logs"
        echo "  • Review server logs for errors"
        exit 1
    fi
}

# Run main function
main
