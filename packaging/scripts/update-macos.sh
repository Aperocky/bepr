#!/bin/sh
set -eu

REPO="Aperocky/bepr"

if [ $# -ge 1 ]; then
    LATEST="${1#v}"
    echo "Installing specified version: $LATEST"
else
    API="https://api.github.com/repos/$REPO/releases/latest"
    echo "Fetching latest release..."
    LATEST=$(curl -fsSL "$API" | grep '"tag_name"' | sed 's/.*"tag_name": *"v\([^"]*\)".*/\1/')
    if [ -z "$LATEST" ]; then
        echo "Failed to fetch latest version" >&2
        exit 1
    fi
    echo "Latest version: $LATEST"

    CURRENT=""
    if command -v bepr >/dev/null 2>&1; then
        CURRENT=$(bepr --version 2>/dev/null | awk '{print $2}' || true)
    fi
    if [ "$CURRENT" = "$LATEST" ]; then
        echo "Already at $LATEST, nothing to do."
        exit 0
    fi
fi

URL="https://github.com/$REPO/releases/download/v${LATEST}/bepr-${LATEST}.pkg"
TMP=$(mktemp /tmp/bepr-XXXXXX.pkg)
echo "Downloading $URL..."
curl -fsSL -o "$TMP" "$URL"

echo "Installing..."
sudo installer -pkg "$TMP" -target /
rm -f "$TMP"

echo "Restarting bepr service..."
sudo launchctl kickstart -k system/com.bepr || true

echo "Done. bepr $LATEST installed."
