#!/bin/bash
# check_latest_report.sh
# Script to check if the latest_report.html link is working properly

REPORTS_DIR="$(dirname "$(readlink -f "$0")")/reports"
LATEST_LINK="$REPORTS_DIR/latest_report.html"

echo "Checking latest_report.html link..."
echo "Reports directory: $REPORTS_DIR"

# Check if the link exists
if [ -e "$LATEST_LINK" ]; then
    if [ -L "$LATEST_LINK" ]; then
        # It's a symlink
        TARGET=$(readlink "$LATEST_LINK")
        echo "Latest report link is a symlink pointing to: $TARGET"
        
        if [ -e "$REPORTS_DIR/$TARGET" ]; then
            echo "✅ The target file exists - link is VALID"
        else
            echo "❌ ERROR: The target file does not exist - link is BROKEN"
            echo "Would you like to fix it? (y/n)"
            read -r answer
            if [ "$answer" = "y" ]; then
                ./update_latest_report.sh
            fi
        fi
    else
        # It's a regular file
        echo "Latest report link is a regular file (not a symlink)"
        echo "Size: $(du -h "$LATEST_LINK" | cut -f1)"
        echo "✅ File exists and can be accessed"
    fi
else
    echo "❌ ERROR: latest_report.html does not exist"
    echo "Would you like to create it? (y/n)"
    read -r answer
    if [ "$answer" = "y" ]; then
        ./update_latest_report.sh
    fi
fi

# List all report files
echo -e "\nAvailable report files:"
find "$REPORTS_DIR" -name "security_report_*.html" -type f | sort -r

exit 0
