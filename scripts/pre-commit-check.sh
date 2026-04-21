#!/bin/bash
# Pre-commit hook: scan staged files for org-specific data.
# Install: cp scripts/pre-commit-check.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
#
# Reads patterns from policy.yaml naming_regex and search_base,
# then greps staged files for matches. Exits non-zero to block the commit.

set -e

# Extract org prefixes from policy.yaml naming_regex
if [ -f policy.yaml ]; then
  PREFIXES=$(grep 'naming_regex' policy.yaml | grep -oP '\(([A-Z|]+)\)' | tr -d '()' | tr '|' '\n')
  SEARCH_BASE=$(grep 'search_base' policy.yaml | sed 's/.*: *"//' | sed 's/".*//')
else
  echo "WARNING: policy.yaml not found, skipping org-data check"
  exit 0
fi

if [ -z "$PREFIXES" ] && [ -z "$SEARCH_BASE" ]; then
  exit 0
fi

# Build grep pattern from prefixes
PATTERN=""
while IFS= read -r prefix; do
  [ -z "$prefix" ] && continue
  if [ -z "$PATTERN" ]; then
    PATTERN="$prefix"
  else
    PATTERN="$PATTERN|$prefix"
  fi
done <<< "$PREFIXES"

# Add search_base components if present
if [ -n "$SEARCH_BASE" ]; then
  # Extract the domain part (e.g. DC=example,DC=com -> example.com)
  DOMAIN=$(echo "$SEARCH_BASE" | grep -oP 'DC=\K[^,]+' | paste -sd '.')
  if [ -n "$DOMAIN" ]; then
    PATTERN="$PATTERN|$DOMAIN"
  fi
  # Add the full search_base path
  PATTERN="$PATTERN|$(echo "$SEARCH_BASE" | sed 's/[.[\*^$()+?{|\\]/\\&/g')"
fi

if [ -z "$PATTERN" ]; then
  exit 0
fi

# Check staged files (exclude gitignored patterns and binary files)
VIOLATIONS=""
for file in $(git diff --cached --name-only --diff-filter=ACM); do
  # Skip files that should be allowed to have org data
  case "$file" in
    policy.yaml|*.db|*.db-shm|*.db-wal|.kiro/*|.hypothesis/*) continue ;;
  esac

  # Skip binary files
  if file --mime "$file" 2>/dev/null | grep -q 'binary'; then
    continue
  fi

  if [ -f "$file" ]; then
    MATCHES=$(grep -nEi "$PATTERN" "$file" 2>/dev/null || true)
    if [ -n "$MATCHES" ]; then
      VIOLATIONS="$VIOLATIONS\n  $file:\n$MATCHES\n"
    fi
  fi
done

if [ -n "$VIOLATIONS" ]; then
  echo "BLOCKED: Org-specific data found in staged files:"
  echo -e "$VIOLATIONS"
  echo ""
  echo "Replace with generic placeholders (ACME-, example.com, jsmith, etc.)"
  echo "See .kiro/steering/no-org-data.md for details."
  echo ""
  echo "To bypass (emergency only): git commit --no-verify"
  exit 1
fi

exit 0
