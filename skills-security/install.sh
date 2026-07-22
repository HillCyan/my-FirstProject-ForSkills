#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${1:-https://github.com/Damond-Fung/skills-security.git}"
BRANCH="${BRANCH:-main}"
INSTALL_ROOT="${INSTALL_ROOT:-$HOME/.trae/skills}"
SKILL_NAME="${SKILL_NAME:-skills-security}"

if ! command -v git >/dev/null 2>&1; then
  echo "Git is required. Please install Git first."
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
  echo "Python 3 is required. Please install Python first."
  exit 1
fi

mkdir -p "$INSTALL_ROOT"
TARGET_PATH="$INSTALL_ROOT/$SKILL_NAME"

rm -rf "$TARGET_PATH"
git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$TARGET_PATH" >/dev/null 2>&1
rm -rf "$TARGET_PATH/.git"

echo "Installed to: $TARGET_PATH"
echo "Run: python3 \"$TARGET_PATH/main.py\" <skills_dir>"
