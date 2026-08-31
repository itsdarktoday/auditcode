#!/usr/bin/env bash
# init-audit.sh — create the ultimate-audit working directory skeleton
# Usage: bash init-audit.sh [TARGET_DIR]  (default: .)
set -euo pipefail

TARGET="${1:-.}"
AUDIT_DIR="$TARGET/ultimate-audit"

mkdir -p "$AUDIT_DIR"/{poc,fuzz,evidence}

cat > "$AUDIT_DIR/status.md" <<EOF
# Audit status
Target: $TARGET
Started: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Effort mode: (unset — resolved by Phase 0)
Tooling available: (unset — detected by Phase 0)
Phase: 0 (setup)
EOF

echo "Created $AUDIT_DIR (status.md, poc/, fuzz/, evidence/)"
