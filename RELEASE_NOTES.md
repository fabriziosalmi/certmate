# Release v1.7.0

## 🎉 New Features

### Issue #53: Local Authentication Support
- **Full user management system** with username/password authentication
- Password hashing using SHA-256 with cryptographic salt
- Session-based authentication with secure HTTP-only cookies
- User CRUD operations (Create, Read, Update, Delete)
- Role-based access control (admin/user roles)
- Login page with modern UI design
- Toggle to enable/disable local authentication
- Protection against deleting the last admin user

### Issue #48: SAN (Subject Alternative Names) Certificate Support
- Create certificates with multiple domains in a single certificate
- New `san_domains` field in API for specifying additional domains
- Comma-separated SAN input in web UI
- Automatic deduplication of domain entries
- Full support across all DNS providers

## 🐛 Bug Fixes

### Issue #54: Settings Save - API Bearer Token Required Error
- Added missing API Bearer Token input field to settings form
- Added Cache TTL configuration field
- Token generation button with cryptographic random token
- Conditional validation: token required only after initial setup
- Auto-generation of token during first-time setup

### Issue #50: Certificates Not Showing After Generation
- Fixed certificate listing to scan both settings AND filesystem
- Certificates created outside settings now properly displayed
- Unified domain discovery from multiple sources
- Automatic deduplication using set-based approach

### Issue #49: Better Error Messages
- Added descriptive hints to all validation errors
- Pre-validation checks before async operations
- Specific error hints for common issues:
  - DNS provider authentication failures
  - Rate limiting from certificate authorities
  - DNS propagation timeouts
  - Missing configuration
- Clear guidance on how to resolve each error type

## 📋 Technical Changes
- Enhanced `AuthManager` class in `modules/core/auth.py`
- New `login.html` template
- Updated `require_auth` decorator to support both session and bearer token
- Modified `CertificateList.get()` to scan certificate directories
- Extended `create_certificate()` to accept `san_domains` parameter
- Added `san_domains` field to API models

## 🧪 Testing
- All 32 existing tests pass
- No regressions detected

---

# Release v1.2.1

## Bug Fixes

### Fix #47: Complete fix for Save Settings not working

**Root Cause:** The `saveSettings()` function was trying to get email from `formData.get('email')`, but no field with `name="email"` existed in the form. Additionally, the Private CA configuration panel wasn't being shown correctly due to ID mapping mismatch (`private_ca` → `private_ca-config` instead of `private-ca-config`).

**Solution:**
1. Modified `saveSettings()` to extract email from the selected CA provider's configuration section (Let's Encrypt, DigiCert, or Private CA)
2. Added explicit `caProviderToConfigId` mapping to correctly handle the `private_ca` → `private-ca-config` ID translation
3. Improved error messages to indicate which CA provider section requires the email address

**Changes:**
- `templates/settings.html`: Updated email collection logic and CA provider config ID mapping

**Testing:**
- Verified settings save correctly for all CA providers (Let's Encrypt, DigiCert, Private CA)
- Confirmed no more "An invalid form control is not focusable" browser console errors
- Validated proper show/hide of CA configuration sections

Closes #47
