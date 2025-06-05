# AI Security Logger Test Tools

This directory contains tools for testing and maintaining the AI Security Logger system.

## Docker Management Tools

- `check_docker_container.sh` - Checks if the Docker container is running and starts it if needed
- `docker_test_logs.sh` - Tests the log generation functionality in the Docker container

## Testing Tools

- `test_endpoint.sh` - Tests the `/generate_logs` endpoint directly
- `test_generate_logs.sh` - Tests the log generation script directly
- `test_empty_logs.py` - Tests system behavior with empty log directories
- `test_fix.sh` - Troubleshooting script for various issues
- `run_tests.py` - Runs the test suite

## Database Tools

- `init_db.py` - Initializes the threats database schema

## Log Tools

- `generate_test_logs.py` - Generates sample log data for testing

## Report Tools

- `check_latest_report.sh` - Checks if the latest report is correctly linked
- `update_latest_report.sh` - Updates the latest_report.html link
- `rebuild.sh` - Rebuilds the system

## Usage Examples

### Check Docker Container Status
```bash
./check_docker_container.sh
```

### Generate Test Logs
```bash
./docker_test_logs.sh
```

### Manual Log Generation
```bash
./generate_test_logs.py -n 10 -i 0.1 -a generic
```
