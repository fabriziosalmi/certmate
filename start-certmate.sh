#!/bin/bash
# Complete script to build and run CertMate with existing certificates
# Respects existing settings and attempts to restore from backups when needed

set -e

echo "🚀 Building and running CertMate with existing certificates..."

# Note: This script uses Docker to avoid local Python dependency conflicts
# If you see certbot/josepy errors, that's expected - we use Docker containers instead

# Function to ensure all necessary directories exist with proper permissions
ensure_directories() {
    local dirs=("./certificates" "./data" "./backups" "./backups/settings" "./backups/certificates" "./logs" "./letsencrypt" "./letsencrypt/config" "./letsencrypt/logs" "./letsencrypt/work")
    
    for dir in "${dirs[@]}"; do
        if [ ! -d "$dir" ]; then
            echo "📁 Creating directory: $dir"
            mkdir -p "$dir"
        fi
    done
    
    # Ensure proper permissions for data and backup directories
    chmod 755 ./data ./backups 2>/dev/null || true
    chmod 644 ./data/settings.json 2>/dev/null || true
}

# Ensure all necessary directories exist
ensure_directories

# Function to check if a certificate directory contains valid certificates
check_valid_certificate() {
    local domain_dir="$1"
    if [ -f "$domain_dir/fullchain.pem" ] && [ -f "$domain_dir/privkey.pem" ]; then
        return 0
    fi
    return 1
}

# Function to find the best settings backup with comprehensive fallback strategy
find_best_settings_backup() {
    local backup_dir="./backups/settings"
    local backup_file=""
    
    # Check multiple possible backup locations for backward compatibility
    local backup_locations=(
        "./backups/settings"
        "./backups"
        "./data/backups"
        "./backup"
        "./"
    )
    
    echo "🔍 Searching for settings backups in multiple locations..."
    
    for location in "${backup_locations[@]}"; do
        if [ -d "$location" ]; then
            echo "  📁 Checking: $location"
            
            # Look for various backup file patterns (backward compatibility)
            local backup_patterns=(
                "settings*.json"
                "settings*.bak"
                "config*.json"
                "certmate*.json"
                "*.settings.json"
                "backup*.json"
            )
            
            for pattern in "${backup_patterns[@]}"; do
                local found_files=$(find "$location" -maxdepth 1 -name "$pattern" -type f 2>/dev/null)
                if [ -n "$found_files" ]; then
                    echo "    ✓ Found backup files matching: $pattern"
                fi
            done
        fi
    done
    
    # Priority 1: Recent backups with domains configured
    echo "🎯 Priority 1: Looking for backups with configured domains..."
    backup_file=$(find "${backup_locations[@]}" -maxdepth 1 -name "*.json" -type f 2>/dev/null | \
        xargs grep -l '"domains".*\[[^]]\+\]' 2>/dev/null | \
        xargs ls -t 2>/dev/null | head -1)
    
    if [ -n "$backup_file" ] && [ -f "$backup_file" ]; then
        echo "  ✅ Found backup with domains: $(basename "$backup_file")"
        echo "$backup_file"
        return 0
    fi
    
    # Priority 2: Backups with email configured (indicating setup completion)
    echo "🎯 Priority 2: Looking for backups with email configuration..."
    backup_file=$(find "${backup_locations[@]}" -maxdepth 1 -name "*.json" -type f 2>/dev/null | \
        xargs grep -l '"email".*"[^"]\+@[^"]\+"' 2>/dev/null | \
        xargs ls -t 2>/dev/null | head -1)
    
    if [ -n "$backup_file" ] && [ -f "$backup_file" ]; then
        local backup_age=$(stat -f "%m" "$backup_file" 2>/dev/null || stat -c "%Y" "$backup_file" 2>/dev/null || echo "0")
        local current_time=$(date +%s)
        local age_days=$(( (current_time - backup_age) / 86400 ))
        
        echo "  📅 Found backup with email (age: $age_days days): $(basename "$backup_file")"
        
        # Accept backups up to 30 days old if they have meaningful configuration
        if [ $age_days -le 30 ]; then
            echo "  ✅ Backup is acceptable (within 30 days)"
            echo "$backup_file"
            return 0
        fi
    fi
    
    # Priority 3: Any recent backup with DNS provider configuration
    echo "🎯 Priority 3: Looking for backups with DNS provider settings..."
    backup_file=$(find "${backup_locations[@]}" -maxdepth 1 -name "*.json" -type f 2>/dev/null | \
        xargs grep -l '"dns_provider"' 2>/dev/null | \
        xargs ls -t 2>/dev/null | head -1)
    
    if [ -n "$backup_file" ] && [ -f "$backup_file" ]; then
        local backup_age=$(stat -f "%m" "$backup_file" 2>/dev/null || stat -c "%Y" "$backup_file" 2>/dev/null || echo "0")
        local current_time=$(date +%s)
        local age_days=$(( (current_time - backup_age) / 86400 ))
        
        echo "  📅 Found backup with DNS provider (age: $age_days days): $(basename "$backup_file")"
        
        if [ $age_days -le 7 ]; then
            echo "  ✅ Recent DNS provider backup is acceptable"
            echo "$backup_file"
            return 0
        fi
    fi
    
    # Priority 4: Any JSON file that looks like settings (most recent)
    echo "🎯 Priority 4: Looking for any settings-like JSON files..."
    backup_file=$(find "${backup_locations[@]}" -maxdepth 1 -name "*.json" -type f 2>/dev/null | \
        xargs grep -l '"api_bearer_token"\|"setup_completed"\|"auto_renew"' 2>/dev/null | \
        xargs ls -t 2>/dev/null | head -1)
    
    if [ -n "$backup_file" ] && [ -f "$backup_file" ]; then
        echo "  📄 Found settings-like file: $(basename "$backup_file")"
        echo "$backup_file"
        return 0
    fi
    
    echo "  ❌ No suitable backup files found"
    return 1
}

# Function to restore settings from backup with comprehensive fallback strategy
restore_settings_from_backup() {
    local backup_file="$1"
    local settings_file="$2"
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    
    echo "🔄 Restoring settings from backup: $(basename "$backup_file")"
    
    # Create backup of current settings before restore
    if [ -f "$settings_file" ]; then
        cp "$settings_file" "./backups/settings/settings_${timestamp}_pre_restore.json"
        echo "💾 Created pre-restore backup"
    fi
    
    if command -v jq >/dev/null 2>&1; then
        # Read backup data and handle both wrapped and direct formats
        local backup_data=$(cat "$backup_file")
        local settings_data=""
        
        # Check if backup has wrapped format (with metadata)
        if echo "$backup_data" | jq -e '.settings' >/dev/null 2>&1; then
            echo "📄 Processing wrapped backup format"
            settings_data=$(echo "$backup_data" | jq '.settings')
        elif echo "$backup_data" | jq -e '.metadata' >/dev/null 2>&1; then
            echo "📄 Processing metadata backup format"
            settings_data=$(echo "$backup_data" | jq 'del(.metadata)')
        else
            echo "📄 Processing direct backup format"
            settings_data="$backup_data"
        fi
        
        # Validate restored settings structure
        if echo "$settings_data" | jq -e 'type == "object"' >/dev/null 2>&1; then
            echo "$settings_data" | jq '.' > "$settings_file"
            echo "✅ Settings restored successfully from backup"
            return 0
        else
            echo "❌ Invalid settings structure in backup"
            return 1
        fi
    else
        # Fallback without jq - direct copy
        echo "⚠️  jq not available - attempting direct copy"
        if [ -f "$backup_file" ]; then
            cp "$backup_file" "$settings_file"
            echo "✅ Settings restored via direct copy"
            return 0
        fi
    fi
    
    return 1
}

# Function to migrate legacy settings formats and ensure compatibility
migrate_legacy_settings() {
    local settings_file="$1"
    local needs_migration=false
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    
    echo "🔄 Checking if settings migration is needed..."
    
    # Create backup before any migration
    cp "$settings_file" "./backups/settings/settings_${timestamp}_pre_migration.json"
    
    # Check for various legacy format issues and fix them
    if command -v jq >/dev/null 2>&1; then
        local temp_file=$(mktemp)
        
        # Ensure all required fields exist with default values
        local required_fields=(
            "domains:[]"
            "email:\"\""
            "auto_renew:true"
            "setup_completed:false"
            "dns_provider:\"cloudflare\""
            "dns_providers:{}"
        )
        
        # Start with current settings
        jq '.' "$settings_file" > "$temp_file"
        
        # Add missing fields with defaults
        for field_def in "${required_fields[@]}"; do
            local field_name=$(echo "$field_def" | cut -d: -f1)
            local field_default=$(echo "$field_def" | cut -d: -f2-)
            
            if ! jq -e ".$field_name" "$temp_file" >/dev/null 2>&1; then
                echo "  📝 Adding missing field: $field_name"
                jq --argjson value "$field_default" ". + {\"$field_name\": \$value}" "$temp_file" > "$temp_file.tmp"
                mv "$temp_file.tmp" "$temp_file"
                needs_migration=true
            fi
        done
        
        # Ensure api_bearer_token exists
        if ! jq -e '.api_bearer_token' "$temp_file" >/dev/null 2>&1 || [ "$(jq -r '.api_bearer_token' "$temp_file")" = "null" ] || [ "$(jq -r '.api_bearer_token' "$temp_file")" = "" ]; then
            echo "  🔑 Generating missing API bearer token"
            local new_token=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
            jq --arg token "$new_token" '.api_bearer_token = $token' "$temp_file" > "$temp_file.tmp"
            mv "$temp_file.tmp" "$temp_file"
            needs_migration=true
        fi
        
        # Ensure certificate_storage structure exists
        if ! jq -e '.certificate_storage' "$temp_file" >/dev/null 2>&1; then
            echo "  📁 Adding certificate storage configuration"
            local storage_config='{
                "backend": "local_filesystem",
                "cert_dir": "certificates",
                "azure_keyvault": {
                    "vault_url": "",
                    "client_id": "",
                    "client_secret": "",
                    "tenant_id": ""
                },
                "aws_secrets_manager": {
                    "region": "us-east-1",
                    "access_key_id": "",
                    "secret_access_key": ""
                },
                "hashicorp_vault": {
                    "vault_url": "",
                    "vault_token": "",
                    "mount_point": "secret",
                    "engine_version": "v2"
                },
                "infisical": {
                    "site_url": "https://app.infisical.com",
                    "client_id": "",
                    "client_secret": "",
                    "project_id": "",
                    "environment": "prod"
                }
            }'
            jq --argjson storage "$storage_config" '.certificate_storage = $storage' "$temp_file" > "$temp_file.tmp"
            mv "$temp_file.tmp" "$temp_file"
            needs_migration=true
        fi
        
        # Convert legacy cloudflare_token to dns_providers format if needed
        local cf_token=$(jq -r '.cloudflare_token // ""' "$temp_file")
        if [ -n "$cf_token" ] && [ "$cf_token" != "null" ] && [ "$cf_token" != "" ]; then
            echo "  🔄 Migrating legacy Cloudflare token to new dns_providers format"
            jq --arg token "$cf_token" '.dns_providers.cloudflare = {"api_token": $token}' "$temp_file" > "$temp_file.tmp"
            mv "$temp_file.tmp" "$temp_file"
            needs_migration=true
        fi
        
        # Apply migration if needed
        if [ "$needs_migration" = true ]; then
            mv "$temp_file" "$settings_file"
            echo "  ✅ Settings migrated successfully"
            echo "  💾 Pre-migration backup: ./backups/settings/settings_${timestamp}_pre_migration.json"
        else
            rm -f "$temp_file"
            echo "  ✅ Settings already up to date"
        fi
        
    else
        echo "  ⚠️  jq not available - skipping automatic migration"
    fi
}
# Function to auto-populate domains from certificate folders while preserving other settings
auto_populate_domains() {
    local settings_file="$1"
    local domains_json="[]"
    local domain_count=0
    
    echo "🔍 Auto-detecting domains from certificate folders..."
    
    if [ -d "./certificates" ]; then
        local temp_domains=()
        
        for cert_dir in ./certificates/*/; do
            if [ -d "$cert_dir" ]; then
                local domain_name=$(basename "$cert_dir")
                
                # Skip invalid domain names - comprehensive filtering for test/fake domains
                if [[ "$domain_name" == "invalid.."* ]] || \
                   [[ "$domain_name" == "*invalid*" ]] || \
                   [[ "$domain_name" == "."* ]] || \
                   [[ "$domain_name" == ".." ]] || \
                   [[ "$domain_name" == *".."* ]] || \
                   [[ "$domain_name" == *"localhost"* ]] || \
                   [[ "$domain_name" == "example.com" ]] || \
                   [[ "$domain_name" == "test.example.com" ]] || \
                   [[ "$domain_name" == "staging.example.com" ]] || \
                   [[ "$domain_name" == "invalid..domain.com" ]] || \
                   [[ "$domain_name" == "test.com" ]] || \
                   [[ "$domain_name" == *"example.org"* ]] || \
                   [[ "$domain_name" == *"example.net"* ]] || \
                   [[ "$domain_name" == *"test."* ]] && [[ "$domain_name" != *".test.certmate.org" ]] || \
                   [[ "$domain_name" == *"staging."* ]] || \
                   [[ "$domain_name" == *"demo."* ]] || \
                   [[ "$domain_name" == *"temp."* ]] || \
                   [[ "$domain_name" == *".local"* ]] || \
                   [[ ${#domain_name} -lt 4 ]] || \
                   [[ "$domain_name" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    echo "  ⚠️  Skipping test/invalid/example domain: $domain_name"
                    continue
                fi
                
                # Check if it has valid certificates
                if check_valid_certificate "$cert_dir"; then
                    temp_domains+=("$domain_name")
                    echo "  ✅ Found valid certificates for: $domain_name"
                    ((domain_count++))
                else
                    echo "  ⚠️  Incomplete certificates for: $domain_name (missing fullchain.pem or privkey.pem)"
                fi
            fi
        done
        
        # Build JSON array
        if [ ${#temp_domains[@]} -gt 0 ]; then
            domains_json="["
            for i in "${!temp_domains[@]}"; do
                if [ $i -gt 0 ]; then
                    domains_json+=", "
                fi
                domains_json+="\"${temp_domains[$i]}\""
            done
            domains_json+="]"
        fi
    fi
    
    echo "📊 Auto-detected $domain_count valid certificate domains"
    
    # Update settings file with auto-detected domains (preserving other settings)
    if [ $domain_count -gt 0 ] && [ -f "$settings_file" ]; then
        echo "🔧 Updating settings with auto-detected domains..."
        
        # Create a backup of current settings
        local timestamp=$(date '+%Y%m%d_%H%M%S')
        cp "$settings_file" "./backups/settings/settings_${timestamp}_pre_auto_update.json"
        
        # Use jq to update the domains array while preserving all other settings
        if command -v jq >/dev/null 2>&1; then
            # Check if domains already exist and decide what to do
            local existing_domains_count=$(jq '.domains | length' "$settings_file" 2>/dev/null || echo "0")
            
            if [ "$existing_domains_count" -eq 0 ]; then
                echo "  📝 No existing domains - adding auto-detected domains"
                # Create the domains array as proper JSON
                temp_json_file=$(mktemp)
                printf '%s\n' "${temp_domains[@]}" | jq -R . | jq -s . > "$temp_json_file"
                jq --argjson domains "$(cat "$temp_json_file")" '.domains = $domains' "$settings_file" > "$settings_file.tmp" && mv "$settings_file.tmp" "$settings_file"
                rm -f "$temp_json_file"
                echo "  ✅ Updated settings with $domain_count domains"
            else
                echo "  � Found $existing_domains_count existing domains in settings"
                
                # Check if auto-detected domains are different from existing ones
                local existing_domains=($(jq -r '.domains[]' "$settings_file" 2>/dev/null))
                local new_domains=()
                
                for domain in "${temp_domains[@]}"; do
                    local found=false
                    for existing in "${existing_domains[@]}"; do
                        if [ "$domain" = "$existing" ]; then
                            found=true
                            break
                        fi
                    done
                    if [ "$found" = false ]; then
                        new_domains+=("$domain")
                    fi
                done
                
                if [ ${#new_domains[@]} -gt 0 ]; then
                    echo "  🆕 Found ${#new_domains[@]} new domains to add:"
                    printf '    - %s\n' "${new_domains[@]}"
                    
                    # Merge new domains with existing ones
                    all_domains=("${existing_domains[@]}" "${new_domains[@]}")
                    temp_json_file=$(mktemp)
                    printf '%s\n' "${all_domains[@]}" | jq -R . | jq -s . > "$temp_json_file"
                    jq --argjson domains "$(cat "$temp_json_file")" '.domains = $domains' "$settings_file" > "$settings_file.tmp" && mv "$settings_file.tmp" "$settings_file"
                    rm -f "$temp_json_file"
                    echo "  ✅ Merged ${#new_domains[@]} new domains with existing settings"
                else
                    echo "  ✅ All auto-detected domains already exist in settings"
                fi
            fi
        else
            echo "  ⚠️  jq not available - manual domain configuration may be needed"
        fi
        
        echo "💾 Created backup: ./backups/settings/settings_${timestamp}_pre_auto_update.json"
    elif [ $domain_count -eq 0 ]; then
        echo "📭 No valid certificate domains found to auto-populate"
    fi
    
    return $domain_count
}

# Check if certificates exist
if [ ! -d "./certificates" ]; then
    echo "❌ No certificates directory found. Creating empty one..."
    mkdir -p certificates
fi

cert_count=$(find ./certificates -name "*.pem" 2>/dev/null | wc -l)
domain_count=$(find ./certificates -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)

echo "📋 Found $domain_count certificate directories with $cert_count certificate files"

# List certificate domains
if [ $domain_count -gt 0 ]; then
    echo "📁 Certificate domains found:"
    ls -1 certificates/ | head -10
    if [ $domain_count -gt 10 ]; then
        echo "   ... and $((domain_count - 10)) more"
    fi
fi

# Check data directory and backups (already handled by ensure_directories)
echo "✅ All necessary directories are ready"

# Handle settings restoration and domain auto-detection
settings_file="./data/settings.json"
if [ -f "$settings_file" ]; then
    echo "✅ Found existing settings file"
    
    # Check if domains array is empty
    current_domains_count=0
    if command -v jq >/dev/null 2>&1; then
        current_domains_count=$(jq '.domains | length' "$settings_file" 2>/dev/null || echo "0")
    fi
    
    if [ "$current_domains_count" -eq 0 ] && [ $domain_count -gt 0 ]; then
        echo "🔍 Settings has no domains but certificates exist - checking if auto-population is safe..."
        
        # Check if this is a fresh installation or if user has meaningful settings
        local has_email=$(jq -r '.email // ""' "$settings_file" 2>/dev/null | grep -E '.+@.+\..+' || echo "")
        local has_dns_config=$(jq -r '.dns_providers | keys | length' "$settings_file" 2>/dev/null || echo "0")
        local setup_completed=$(jq -r '.setup_completed // false' "$settings_file" 2>/dev/null)
        
        if [ -n "$has_email" ] || [ "$has_dns_config" -gt 0 ] || [ "$setup_completed" = "true" ]; then
            echo "⚠️  Detected existing user configuration - skipping automatic domain population"
            echo "💡 User has configured email: $([ -n "$has_email" ] && echo "Yes" || echo "No")"
            echo "💡 DNS providers configured: $has_dns_config"
            echo "💡 Setup completed: $setup_completed"
            echo "🔧 If you want to add certificate domains, please use the web interface"
            return 0
        fi
        
        # Try to restore from backup first
        best_backup=$(find_best_settings_backup)
        if [ -n "$best_backup" ]; then
            echo "💾 Found suitable settings backup: $(basename "$best_backup")"
            
            # Check backup age for automated decision
            backup_age=$(stat -f "%m" "$best_backup" 2>/dev/null || stat -c "%Y" "$best_backup" 2>/dev/null || echo "0")
            current_time=$(date +%s)
            age_days=$(( (current_time - backup_age) / 86400 ))
            
            echo "📅 Backup is $age_days days old"
            
            if [ $age_days -le 2 ]; then
                echo "� Auto-restoring from recent backup..."
                
                # Create backup of current settings
                timestamp=$(date '+%Y%m%d_%H%M%S')
                cp "$settings_file" "./backups/settings/settings_${timestamp}_pre_restore.json"
                
                # Extract settings from backup (handle both wrapped and direct formats)
                if jq -e '.settings' "$best_backup" >/dev/null 2>&1; then
                    # Wrapped format (newer backups)
                    jq '.settings' "$best_backup" > "$settings_file.tmp"
                    echo "📄 Restored from wrapped backup format"
                else
                    # Direct format (older backups)
                    cp "$best_backup" "$settings_file.tmp"
                    echo "📄 Restored from direct backup format"
                fi
                
                # Now auto-populate domains from certificates while preserving restored settings
                if [ -f "$settings_file.tmp" ]; then
                    mv "$settings_file.tmp" "$settings_file"
                    echo "✅ Restored settings from backup"
                    echo "🔍 Now auto-detecting domains from certificates to update the restored settings..."
                    auto_populate_domains "$settings_file"
                fi
                
                echo "💾 Created pre-restore backup: ./backups/settings/settings_${timestamp}_pre_restore.json"
            else
                echo "📅 Backup is older than 2 days - using auto-detection instead"
                auto_populate_domains "$settings_file"
            fi
        else
            echo "💡 No suitable backup found - auto-detecting domains from certificates..."
            auto_populate_domains "$settings_file"
        fi
    elif [ "$current_domains_count" -eq 0 ] && [ $domain_count -eq 0 ]; then
        echo "📝 No domains configured and no certificates found - fresh installation"
    else
        echo "✅ Settings already contains $current_domains_count configured domains"
        if [ $domain_count -gt 0 ] && [ "$current_domains_count" -ne $domain_count ]; then
            echo "📊 Note: Found $domain_count certificate directories but settings shows $current_domains_count domains"
            echo "💡 You may want to verify domain configuration in the web interface"
        fi
    fi
else
    echo "📝 No settings file found - will be created on first run"
fi

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "⚙️  Creating .env file..."
    cat > .env << EOF
# CertMate Environment Configuration
SECRET_KEY=$(openssl rand -hex 32)
API_BEARER_TOKEN=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
FLASK_ENV=production

# DNS Provider Tokens (set these for your provider)
# CLOUDFLARE_TOKEN=your_cloudflare_token_here
# AWS_ACCESS_KEY_ID=your_aws_key_here
# AWS_SECRET_ACCESS_KEY=your_aws_secret_here
EOF
    echo "✅ Created .env file with secure tokens"
else
    echo "✅ Using existing .env file"
fi

# Build and run with docker-compose
echo "🔨 Building Docker image..."
docker-compose build

echo "🚀 Starting CertMate..."
docker-compose up -d

# Wait for container to start
echo "⏳ Waiting for container to start..."
sleep 5

# Check if container is running
if docker-compose ps | grep -q "Up"; then
    echo "✅ CertMate is running!"
    
    # Check if certificates are visible in container
    echo "🔍 Checking certificates in container..."
    container_cert_count=$(docker-compose exec -T certmate find /app/certificates -name "*.pem" 2>/dev/null | wc -l || echo "0")
    container_domain_count=$(docker-compose exec -T certmate find /app/certificates -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l || echo "0")
    
    echo "📊 Container sees $container_domain_count domains with $container_cert_count certificate files"
    
    # Check final settings state
    if [ -f "./data/settings.json" ] && command -v jq >/dev/null 2>&1; then
        final_domains_count=$(jq '.domains | length' "./data/settings.json" 2>/dev/null || echo "0")
        echo "⚙️  Final settings configuration: $final_domains_count domains"
        
        if [ "$final_domains_count" -gt 0 ]; then
            echo "📋 Configured domains:"
            jq -r '.domains[]' "./data/settings.json" 2>/dev/null | head -5 | sed 's/^/   - /'
            if [ "$final_domains_count" -gt 5 ]; then
                echo "   ... and $((final_domains_count - 5)) more"
            fi
        fi
    fi
    
    if [ "$container_domain_count" -eq "$domain_count" ]; then
        echo "✅ All certificates are properly mounted!"
    else
        echo "⚠️  Certificate count mismatch. Checking permissions..."
        
        # Fix permissions if needed
        echo "🔧 Fixing permissions..."
        docker-compose exec -T certmate chown -R certmate:certmate /app/certificates /app/data /app/logs
    fi
    
    echo ""
    echo "🌐 Access URLs:"
    echo "   Web Interface: http://localhost:8000"
    echo "   API Documentation: http://localhost:8000/docs/"
    echo "   Health Check: http://localhost:8000/health"
    
    echo ""
    echo "🔍 To debug further:"
    echo "   docker-compose logs -f certmate"
    echo "   docker-compose exec certmate ls -la /app/certificates"
    
else
    echo "❌ Failed to start CertMate. Check logs:"
    docker-compose logs certmate
fi
