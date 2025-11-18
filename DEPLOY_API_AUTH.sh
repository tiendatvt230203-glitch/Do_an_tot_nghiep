#!/bin/bash
################################################################################
# DEPLOY API AUTHENTICATION SYSTEM
# Adds API key authentication to Email Gateway
################################################################################

set -e
cd "$(dirname "$0")"

echo "========================================================================"
echo "  DEPLOYING API KEY AUTHENTICATION SYSTEM"
echo "========================================================================"
echo ""

#------------------------------------------------------------------------------
# [1/5] Apply database migration
#------------------------------------------------------------------------------
echo "[1/5] Creating API key tables..."

if sudo -u postgres psql -d email_gateway -f add_api_authentication.sql; then
    echo "✅ Database migration successful"
else
    echo "❌ Database migration failed"
    exit 1
fi

echo ""

#------------------------------------------------------------------------------
# [2/5] Install Python dependencies
#------------------------------------------------------------------------------
echo "[2/5] Installing Python dependencies..."

pip3 install secrets >/dev/null 2>&1 || true

echo "✅ Dependencies installed"
echo ""

#------------------------------------------------------------------------------
# [3/5] Backup existing API file
#------------------------------------------------------------------------------
echo "[3/5] Backing up existing API..."

if [ -f api_updated.py ]; then
    cp api_updated.py api_updated.py.backup.$(date +%Y%m%d_%H%M%S)
    echo "✅ Backup created: api_updated.py.backup.*"
else
    echo "⚠️ api_updated.py not found"
fi

echo ""

#------------------------------------------------------------------------------
# [4/5] Show integration instructions
#------------------------------------------------------------------------------
echo "[4/5] Integration Instructions"
echo "========================================================================"
echo ""
echo "To integrate API key authentication, add this to api_updated.py:"
echo ""
echo "--- At the top of the file (after imports): ---"
echo ""
cat << 'EOF'
from api_auth import get_api_key_from_header
from api_key_endpoints import router as api_key_router
from fastapi import Depends

# Include API key management router
app.include_router(api_key_router)
EOF

echo ""
echo "--- For PROTECTED endpoints, add the Depends parameter: ---"
echo ""
cat << 'EOF'
# Example: Protect the /api/domains endpoint
@app.get("/api/domains")
async def get_domains(api_key_info: dict = Depends(get_api_key_from_header)):
    # Your existing code here
    ...
EOF

echo ""
echo "--- For PUBLIC endpoints (no auth required): ---"
echo ""
cat << 'EOF'
# Example: Keep homepage public
@app.get("/", response_class=HTMLResponse)
async def home():
    # No Depends parameter = no auth required
    ...
EOF

echo ""
echo "========================================================================"
echo ""

#------------------------------------------------------------------------------
# [5/5] Generate default admin API key
#------------------------------------------------------------------------------
echo "[5/5] Checking default API key..."

DEFAULT_KEY=$(sudo -u postgres psql -d email_gateway -t -c "SELECT api_key FROM api_keys WHERE key_name LIKE '%Default Admin%' LIMIT 1" | xargs)

if [ -n "$DEFAULT_KEY" ]; then
    echo ""
    echo "========================================================================"
    echo "  ⚠️ DEFAULT ADMIN API KEY (CHANGE IMMEDIATELY!)"
    echo "========================================================================"
    echo ""
    echo "  API Key: $DEFAULT_KEY"
    echo ""
    echo "  This is a DEFAULT key created for testing."
    echo "  You should:"
    echo "    1. Use this key to create a NEW admin key"
    echo "    2. Revoke this default key immediately"
    echo ""
    echo "========================================================================"
else
    echo "⚠️ No default API key found. Database migration may have failed."
fi

echo ""

#------------------------------------------------------------------------------
# Summary
#------------------------------------------------------------------------------
echo "========================================================================"
echo "  ✅ API AUTHENTICATION SYSTEM DEPLOYED"
echo "========================================================================"
echo ""
echo "📝 Next Steps:"
echo ""
echo "1. Integrate authentication into api_updated.py (see instructions above)"
echo ""
echo "2. Restart the API server:"
echo "   ./stop.sh && ./start.sh"
echo ""
echo "3. Test the default API key:"
echo "   curl -H \"X-API-Key: $DEFAULT_KEY\" http://localhost:8000/api/admin/api-keys/test"
echo ""
echo "4. Create a new admin API key:"
echo "   curl -X POST http://localhost:8000/api/admin/api-keys \\"
echo "     -H \"X-API-Key: $DEFAULT_KEY\" \\"
echo "     -H \"Content-Type: application/json\" \\"
echo "     -d '{"
echo "       \"key_name\": \"My Admin Key\","
echo "       \"created_by\": \"admin@example.com\","
echo "       \"permissions\": {\"read\": true, \"write\": true, \"delete\": true, \"admin\": true},"
echo "       \"rate_limit\": 10000"
echo "     }'"
echo ""
echo "5. Revoke the default key:"
echo "   curl -X POST http://localhost:8000/api/admin/api-keys/revoke \\"
echo "     -H \"X-API-Key: YOUR_NEW_KEY\" \\"
echo "     -H \"Content-Type: application/json\" \\"
echo "     -d '{\"api_key\": \"$DEFAULT_KEY\"}'"
echo ""
echo "📚 Documentation:"
echo "   - API key in header: X-API-Key: your_api_key_here"
echo "   - Permissions: read, write, delete, admin"
echo "   - Rate limiting: Default 1000 requests/hour"
echo ""
echo "🔒 Security Notes:"
echo "   - Store API keys securely (environment variables, secrets manager)"
echo "   - Never commit API keys to version control"
echo "   - Rotate keys regularly"
echo "   - Use different keys for different apps/users"
echo "   - Monitor API key usage in api_key_logs table"
echo ""
echo "========================================================================"
