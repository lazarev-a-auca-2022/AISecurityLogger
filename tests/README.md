# AI Security Logger Test Suite

This directory contains comprehensive tests for the AI-Powered Security Log Processor project. The test suite ensures all functionality works correctly and maintains high code quality.

## Test Structure

```
tests/
├── __init__.py                     # Test package initialization
├── ci_config.py                   # CI/CD configuration
├── fixtures/                      # Test fixtures and utilities
│   └── __init__.py               # Reusable test data and mocks
├── unit/                         # Unit tests for individual components
│   ├── __init__.py
│   ├── test_threat_analyzer.py   # ThreatAnalyzer class tests
│   ├── test_log_ingestor.py      # LogIngestor and LogFileHandler tests
│   ├── test_database.py          # Database operations tests
│   ├── test_report_generator.py  # Report generation tests
│   └── test_settings.py          # Configuration management tests
├── integration/                   # Integration tests
│   ├── __init__.py
│   └── test_integration.py       # End-to-end workflow tests
└── performance/                   # Performance and load tests
    └── test_performance.py       # System performance tests
```

## Test Categories

### Unit Tests (~/unit/)
- **test_threat_analyzer.py**: Tests AI provider integrations, threat analysis, queue management, and error handling
- **test_log_ingestor.py**: Tests log file monitoring, parsing (syslog, nginx, apache), and keyword filtering
- **test_database.py**: Tests SQLite operations, threat storage/retrieval, and concurrent access
- **test_report_generator.py**: Tests HTML/JSON report generation, scheduling, and templating
- **test_settings.py**: Tests configuration loading, environment variables, and validation

### Integration Tests (~/integration/)
- **test_integration.py**: Tests complete workflows, component interaction, and data flow

### Performance Tests (~/performance/)
- **test_performance.py**: Tests system performance, memory usage, and concurrent operations

## Running Tests

### Quick Start

```bash
# Install test dependencies
pip install -r requirements-test.txt

# Run all tests
python run_tests.py all

# Run with coverage
python run_tests.py all --coverage

# Run specific test category
python run_tests.py unit
python run_tests.py integration
python run_tests.py performance
```

### Test Runner Options

The `run_tests.py` script provides several commands:

```bash
# Check requirements and setup
python run_tests.py check

# Run unit tests only
python run_tests.py unit --verbose

# Run integration tests
python run_tests.py integration

# Run all tests with coverage and HTML report
python run_tests.py all --coverage --html

# Run code linting
python run_tests.py lint

# Generate comprehensive test report
python run_tests.py report

# Run specific test file or function
python run_tests.py specific --test-path tests/unit/test_database.py::TestDatabase::test_store_threat
```

### Using pytest Directly

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test file
pytest tests/unit/test_threat_analyzer.py -v

# Run tests with specific marker
pytest tests/ -m "not performance"

# Run tests in parallel
pytest tests/ -n auto

# Run with timeout
pytest tests/ --timeout=300
```

## Test Configuration

### pytest Configuration (pyproject.toml)
- Test discovery patterns
- Timeout settings
- Coverage configuration
- Custom markers
- Asyncio support

### CI/CD Configuration
- GitHub Actions workflow (`.github/workflows/tests.yml`)
- Multi-Python version testing
- Docker testing
- Security scanning
- Artifact collection

## Test Features

### Comprehensive Coverage
- **2,600+ lines** of test code
- Tests for all major components
- Error handling and edge cases
- Concurrent operation testing
- Mock external dependencies

### AI Provider Testing
- OpenRouter integration
- OpenAI API testing
- Google Gemini testing
- Azure OpenAI testing
- Anthropic Claude testing
- Custom API endpoint testing

### Log Format Support
- Syslog format parsing
- Nginx access logs
- Apache error logs
- Generic log formats
- Keyword filtering

### Database Testing
- SQLite operations
- CRUD operations
- Concurrent access
- Data persistence
- Query performance

### Report Testing
- HTML report generation
- JSON report generation
- Template rendering
- Scheduling functionality
- Large dataset handling

### Performance Testing
- Memory usage monitoring
- Processing speed benchmarks
- Concurrent operation limits
- Memory leak detection
- Large dataset handling

## Test Fixtures and Utilities

### MockSettings
Provides configurable mock settings for testing different scenarios.

### LogDataFactory
Creates sample log entries in various formats:
- `create_syslog_entries(count)` - System log entries
- `create_nginx_entries(count)` - Nginx access logs
- `create_apache_entries(count)` - Apache error logs
- `create_generic_entries(count)` - Generic log format

### ThreatDataFactory
Creates sample threat data:
- `create_threat_dict()` - Single threat record
- `create_threat_list(count)` - Multiple threat records

### DatabaseFixture
Manages test database lifecycle:
- Temporary database creation
- Schema setup
- Sample data insertion
- Cleanup after tests

### FileFixture
Manages test files and directories:
- Log file creation
- Configuration file creation
- Directory management
- Cleanup after tests

## Best Practices

### Writing Tests
1. Use descriptive test names
2. Follow AAA pattern (Arrange, Act, Assert)
3. Use appropriate fixtures
4. Mock external dependencies
5. Test both success and failure cases
6. Include edge cases and boundary conditions

### Test Organization
1. Group related tests in classes
2. Use setup/teardown methods appropriately
3. Keep tests independent
4. Use parametrized tests for multiple scenarios
5. Mark tests appropriately (unit, integration, performance)

### Performance Considerations
1. Use temporary databases and files
2. Clean up resources after tests
3. Monitor memory usage in performance tests
4. Use appropriate timeout values
5. Consider test execution time

## Continuous Integration

### GitHub Actions
The CI workflow includes:
- Multi-Python version testing (3.9, 3.10, 3.11)
- Dependency caching
- Coverage reporting
- Docker container testing
- Security scanning
- Artifact collection

### Coverage Requirements
- Minimum 80% code coverage
- HTML and XML coverage reports
- Coverage uploaded to Codecov
- Branch coverage tracking

### Security Scanning
- Bandit security analysis
- Safety dependency checking
- Vulnerability reporting

## Troubleshooting

### Common Issues

1. **Import Errors**
   ```bash
   # Ensure PYTHONPATH includes src directory
   export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
   ```

2. **Database Permissions**
   ```bash
   # Ensure test directory is writable
   chmod 755 tests/
   ```

3. **Missing Dependencies**
   ```bash
   # Install all test dependencies
   pip install -r requirements-test.txt
   ```

4. **Timeout Issues**
   ```bash
   # Increase timeout for slow tests
   pytest tests/ --timeout=600
   ```

### Debug Mode
```bash
# Run with verbose output and no capture
pytest tests/ -v -s --tb=long

# Run single test with debugging
pytest tests/unit/test_database.py::TestDatabase::test_store_threat -v -s
```

## Contributing

When adding new features:
1. Write tests first (TDD approach)
2. Ensure all tests pass
3. Maintain or improve coverage
4. Update documentation
5. Follow existing test patterns

## Test Metrics

Current test suite statistics:
- **Total test files**: 7
- **Total test functions**: 150+
- **Code coverage**: 90%+
- **Lines of test code**: 2,600+
- **Supported Python versions**: 3.9, 3.10, 3.11
- **Test execution time**: < 5 minutes

## Support

For test-related issues:
1. Check this README
2. Review test output and error messages
3. Check CI/CD logs
4. Ensure all dependencies are installed
5. Verify Python version compatibility
