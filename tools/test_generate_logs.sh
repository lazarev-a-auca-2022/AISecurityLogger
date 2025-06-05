#!/bin/bash
python3 generate_test_logs.py -n 10 -i 0.1 -a generic -f "../data/logs/test_manual.log"# Script to manually test the generate_test_logs.py functionality
echo "Testing generate_test_logs.py..."

# Make sure we're in the right directory
cd "$(dirname "$0")"

# Create logs directory if it doesn't exist
mkdir -p ../data/logs

# Run the generate_test_logs.py script
python3 generate_test_logs.py -n 30 -i 0.1 -a generic -f "../data/logs/test_manual.log"

# Check the result
if [ $? -eq 0 ]; then
    echo "✅ Success! Test logs generated successfully."
    echo "📄 Log file created at: ../data/logs/test_manual.log"
    echo "📊 Log file contents (first 5 lines):"
    head -n 5 ../data/logs/test_manual.log
else
    echo "❌ Error! Failed to generate test logs."
fi
