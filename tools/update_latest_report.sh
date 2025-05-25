#!/bin/bash
# update_latest_report.sh
# Script to find the latest report and update the latest_report.html link

set -e

# Define the reports directory
REPORTS_DIR="$(dirname "$(readlink -f "$0")")/reports"

# Find the newest HTML report file
LATEST_REPORT=$(find "$REPORTS_DIR" -name "security_report_*.html" -type f -printf "%T@ %p\n" | sort -nr | head -1 | cut -d' ' -f2-)

if [ -z "$LATEST_REPORT" ]; then
    echo "Error: No security reports found"
    exit 1
fi

LATEST_LINK="$REPORTS_DIR/latest_report.html"

# Get the basename for relative linking
REPORT_BASENAME=$(basename "$LATEST_REPORT")

echo "Found latest report: $REPORT_BASENAME"

# Remove existing link if it exists
if [ -e "$LATEST_LINK" ]; then
    rm "$LATEST_LINK"
    echo "Removed existing latest_report.html"
fi

# Create new symlink
cd "$REPORTS_DIR" && ln -s "$REPORT_BASENAME" "latest_report.html"
echo "Created new symlink: latest_report.html -> $REPORT_BASENAME"

# Verify the link was created
if [ -L "$LATEST_LINK" ]; then
    echo "Success: latest_report.html now points to $REPORT_BASENAME"
else
    echo "Error: Failed to create symlink"
    exit 1
fi

exit 0
