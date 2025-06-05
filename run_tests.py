#!/usr/bin/env python3
"""
Test Runner for AI Security Logger
Executes all unit and integration tests with detailed reporting
"""

import os
import sys
import subprocess
import argparse
import time
from pathlib import Path

def run_command(cmd, capture_output=True):
    """Run a shell command and return the result"""
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=capture_output, 
            text=True,
            cwd=Path(__file__).parent
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return 1, "", str(e)

def check_requirements():
    """Check if required packages are installed"""
    print("🔍 Checking requirements...")
    required_packages = [
        'pytest',
        'pytest-asyncio',
        'pytest-cov',
        'pytest-html'
    ]
    
    missing_packages = []
    for package in required_packages:
        returncode, _, _ = run_command(f"python -c 'import {package.replace('-', '_')}'")
        if returncode != 0:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"❌ Missing packages: {', '.join(missing_packages)}")
        print("Installing missing packages...")
        for package in missing_packages:
            print(f"  Installing {package}...")
            returncode, stdout, stderr = run_command(f"pip install {package}")
            if returncode != 0:
                print(f"    ❌ Failed to install {package}: {stderr}")
                return False
            else:
                print(f"    ✅ Installed {package}")
    else:
        print("✅ All required packages are installed")
    
    return True

def run_unit_tests(verbose=False, coverage=False):
    """Run unit tests"""
    print("\n🧪 Running unit tests...")
    
    cmd = "python -m pytest tests/unit/"
    if verbose:
        cmd += " -v"
    if coverage:
        cmd += " --cov=src --cov-report=html --cov-report=term"
    
    cmd += " --tb=short"
    
    start_time = time.time()
    returncode, stdout, stderr = run_command(cmd, capture_output=False)
    end_time = time.time()
    
    print(f"\n⏱️  Unit tests completed in {end_time - start_time:.2f} seconds")
    return returncode == 0

def run_integration_tests(verbose=False):
    """Run integration tests"""
    print("\n🔗 Running integration tests...")
    
    cmd = "python -m pytest tests/integration/"
    if verbose:
        cmd += " -v"
    cmd += " --tb=short"
    
    start_time = time.time()
    returncode, stdout, stderr = run_command(cmd, capture_output=False)
    end_time = time.time()
    
    print(f"\n⏱️  Integration tests completed in {end_time - start_time:.2f} seconds")
    return returncode == 0

def run_all_tests(verbose=False, coverage=False, html_report=False):
    """Run all tests"""
    print("\n🚀 Running all tests...")
    
    cmd = "python -m pytest tests/"
    if verbose:
        cmd += " -v"
    if coverage:
        cmd += " --cov=src --cov-report=html --cov-report=term"
    if html_report:
        cmd += " --html=test_reports/report.html --self-contained-html"
        # Create reports directory if it doesn't exist
        os.makedirs("test_reports", exist_ok=True)
    
    cmd += " --tb=short"
    
    start_time = time.time()
    returncode, stdout, stderr = run_command(cmd, capture_output=False)
    end_time = time.time()
    
    print(f"\n⏱️  All tests completed in {end_time - start_time:.2f} seconds")
    return returncode == 0

def run_specific_test(test_path, verbose=False):
    """Run a specific test file or test function"""
    print(f"\n🎯 Running specific test: {test_path}")
    
    cmd = f"python -m pytest {test_path}"
    if verbose:
        cmd += " -v"
    cmd += " --tb=short"
    
    start_time = time.time()
    returncode, stdout, stderr = run_command(cmd, capture_output=False)
    end_time = time.time()
    
    print(f"\n⏱️  Test completed in {end_time - start_time:.2f} seconds")
    return returncode == 0

def run_linting():
    """Run code linting"""
    print("\n🔍 Running code linting...")
    
    # Check if flake8 is available
    returncode, _, _ = run_command("python -c 'import flake8'")
    if returncode != 0:
        print("Installing flake8...")
        run_command("pip install flake8")
    
    cmd = "python -m flake8 src/ tests/ --max-line-length=100 --ignore=E501,W503"
    returncode, stdout, stderr = run_command(cmd)
    
    if returncode == 0:
        print("✅ Linting passed")
        return True
    else:
        print("❌ Linting failed:")
        print(stderr)
        return False

def generate_test_report():
    """Generate a comprehensive test report"""
    print("\n📊 Generating comprehensive test report...")
    
    cmd = (
        "python -m pytest tests/ "
        "--cov=src "
        "--cov-report=html:test_reports/coverage "
        "--cov-report=term "
        "--html=test_reports/test_report.html "
        "--self-contained-html "
        "-v"
    )
    
    os.makedirs("test_reports", exist_ok=True)
    returncode, stdout, stderr = run_command(cmd, capture_output=False)
    
    if returncode == 0:
        print("\n✅ Test report generated successfully!")
        print("📁 Reports available in:")
        print("  - test_reports/test_report.html (Test results)")
        print("  - test_reports/coverage/index.html (Coverage report)")
    else:
        print("❌ Failed to generate test report")
    
    return returncode == 0

def main():
    parser = argparse.ArgumentParser(description="AI Security Logger Test Runner")
    parser.add_argument(
        "command", 
        choices=["unit", "integration", "all", "lint", "report", "check", "specific"],
        help="Test command to run"
    )
    parser.add_argument(
        "--verbose", "-v", 
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--coverage", "-c",
        action="store_true",
        help="Generate coverage report"
    )
    parser.add_argument(
        "--html",
        action="store_true",
        help="Generate HTML report"
    )
    parser.add_argument(
        "--test-path",
        help="Specific test path (for 'specific' command)"
    )
    
    args = parser.parse_args()
    
    print("🔐 AI Security Logger Test Runner")
    print("=" * 50)
    
    # Check requirements first
    if not check_requirements():
        print("❌ Failed to install required packages")
        sys.exit(1)
    
    success = True
    
    if args.command == "check":
        print("✅ Requirements check completed")
        
    elif args.command == "unit":
        success = run_unit_tests(args.verbose, args.coverage)
        
    elif args.command == "integration":
        success = run_integration_tests(args.verbose)
        
    elif args.command == "all":
        success = run_all_tests(args.verbose, args.coverage, args.html)
        
    elif args.command == "lint":
        success = run_linting()
        
    elif args.command == "report":
        success = generate_test_report()
        
    elif args.command == "specific":
        if not args.test_path:
            print("❌ --test-path is required for 'specific' command")
            sys.exit(1)
        success = run_specific_test(args.test_path, args.verbose)
    
    print("\n" + "=" * 50)
    if success:
        print("✅ All tests completed successfully!")
        sys.exit(0)
    else:
        print("❌ Some tests failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
