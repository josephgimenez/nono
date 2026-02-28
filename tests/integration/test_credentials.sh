#!/bin/bash
# Credential Handling Tests
# Tests credential flag parsing, error messages, and env var sanitization.
# These tests do NOT require a keyring daemon or 1Password CLI —
# they exercise parsing, validation, and security boundaries.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Credential Tests ===${NC}"

verify_nono_binary
if ! require_working_sandbox "credential suite"; then
    print_summary
    exit 0
fi

# Create test fixtures
TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

echo ""
echo "Test directory: $TMPDIR"
echo ""

# =============================================================================
# op:// URI Parsing and Validation
# =============================================================================

echo "--- op:// URI Parsing ---"

# Bare op:// URI without =VAR should be rejected with a helpful error
expect_failure "bare op:// URI without =VAR is rejected" \
    "$NONO_BIN" run --allow "$TMPDIR" --env-credential "op://vault/item/field" -- echo "should not run"

expect_output_contains "bare op:// URI error mentions required format" "op://vault/item/field=MY_VAR" \
    "$NONO_BIN" run --allow "$TMPDIR" --env-credential "op://vault/item/field" -- echo "should not run"

# op:// URI with empty var name after = should be rejected
expect_failure "op:// URI with empty var name rejected" \
    "$NONO_BIN" run --allow "$TMPDIR" --env-credential "op://vault/item/field=" -- echo "should not run"

# =============================================================================
# Environment Variable Sanitization
# =============================================================================

echo ""
echo "--- Env Var Sanitization ---"

# 1Password service account token should NOT leak into sandboxed process
export OP_SERVICE_ACCOUNT_TOKEN="test-token-should-not-leak"
expect_output_not_contains "OP_SERVICE_ACCOUNT_TOKEN not leaked to child" "test-token-should-not-leak" \
    "$NONO_BIN" run --allow "$TMPDIR" -- env
unset OP_SERVICE_ACCOUNT_TOKEN

# OP_SESSION_ variables should be blocked
export OP_SESSION_my_account="test-session-should-not-leak"
expect_output_not_contains "OP_SESSION_ variable not leaked to child" "test-session-should-not-leak" \
    "$NONO_BIN" run --allow "$TMPDIR" -- env
unset OP_SESSION_my_account

# OP_CONNECT_TOKEN should be blocked
export OP_CONNECT_TOKEN="test-connect-token"
expect_output_not_contains "OP_CONNECT_TOKEN not leaked to child" "test-connect-token" \
    "$NONO_BIN" run --allow "$TMPDIR" -- env
unset OP_CONNECT_TOKEN

# OP_CONNECT_HOST should be blocked
export OP_CONNECT_HOST="http://localhost:8080"
expect_output_not_contains "OP_CONNECT_HOST not leaked to child" "OP_CONNECT_HOST" \
    "$NONO_BIN" run --allow "$TMPDIR" -- env
unset OP_CONNECT_HOST

# =============================================================================
# Credential Error Handling
# =============================================================================

echo ""
echo "--- Credential Error Handling ---"

# Nonexistent keyring key should fail (no keyring daemon in containers)
expect_failure "nonexistent keyring credential fails gracefully" \
    "$NONO_BIN" run --allow "$TMPDIR" --env-credential "nonexistent_key_12345" -- echo "should not run"

# =============================================================================
# Summary
# =============================================================================

print_summary
