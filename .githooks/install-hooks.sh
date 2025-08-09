#!/bin/bash

# Script to install git hooks

HOOK_DIR="$(git rev-parse --git-dir)/hooks"
SCRIPT_DIR="$(dirname "$0")"

echo "Installing git hooks..."

# Copy pre-commit hook
if [ -f "$SCRIPT_DIR/pre-commit" ]; then
    cp "$SCRIPT_DIR/pre-commit" "$HOOK_DIR/pre-commit"
    chmod +x "$HOOK_DIR/pre-commit"
    echo "✓ Installed pre-commit hook"
else
    echo "✗ pre-commit hook not found"
    exit 1
fi

echo "✅ Git hooks installed successfully!"
echo
echo "To bypass hooks for a commit, use: git commit --no-verify"
echo "To uninstall hooks, delete files in: $HOOK_DIR"