#!/bin/bash

APP_NAME="sbox"
ENTRYPOINT="sbox/run.py"
ICON_PATH="sbox/app.ico"
DIST_DIR="bin"

echo "Cleaning previous builds..."
rm -rf build dist *.spec "$DIST_DIR"

echo "Installing dependencies..."
pip show pyinstaller >/dev/null 2>&1 || pip install pyinstaller

echo "Building executable for $APP_NAME..."
pyinstaller --onefile --windowed --noconfirm \
    --distpath "$DIST_DIR" \
    -n "$APP_NAME" "$ENTRYPOINT" \
    --icon="$ICON_PATH" \
    --add-data "sbox/app.ico;."

rm -r build  *.spec

BIN_PATH_WIN=$(cd "$DIST_DIR" && pwd -W)

echo "Windows path to executable: $BIN_PATH_WIN"
