"""
Continuous Integration Configuration for AI Security Logger Tests
Provides configuration for automated testing in CI/CD pipelines
"""

import os
import sys
import json
import subprocess
from pathlib import Path


class CIConfig:
    """Configuration manager for CI/CD environments"""
    
    @staticmethod
    def detect_ci_environment():
        """Detect which CI environment we're running in"""
        if os.getenv('GITHUB_ACTIONS'):
            return 'github_actions'
        elif os.getenv('TRAVIS'):
            return 'travis'
        elif os.getenv('JENKINS_URL'):
            return 'jenkins'
        elif os.getenv('CIRCLECI'):
            return 'circleci'
        elif os.getenv('GITLAB_CI'):
            return 'gitlab'
        else:
            return 'local'
    
    @staticmethod
    def get_test_config():
        """Get test configuration based on environment"""
        env = CIConfig.detect_ci_environment()
        
        base_config = {
            'test_timeout': 300,  # 5 minutes
            'max_workers': 2,
            'coverage_threshold': 80,
            'performance_tests': False,
            'integration_tests': True,
            'report_format': ['junit', 'html'],
            'artifacts_dir': 'test_artifacts'
        }
        
        if env == 'github_actions':
            base_config.update({
                'max_workers': 4,
                'performance_tests': True,
                'artifacts_dir': os.getenv('GITHUB_WORKSPACE', '.') + '/test_artifacts'
            })
        elif env == 'travis':
            base_config.update({
                'max_workers': 2,
                'test_timeout': 600  # Travis can be slower
            })
        elif env == 'local':
            base_config.update({
                'max_workers': os.cpu_count() or 4,
                'performance_tests': True,
                'coverage_threshold': 90
            })
        
        return base_config
    
    @staticmethod
    def setup_environment():
        """Setup environment for testing"""
        config = CIConfig.get_test_config()
        
        # Create artifacts directory
        artifacts_dir = config['artifacts_dir']
        os.makedirs(artifacts_dir, exist_ok=True)
        
        # Set environment variables
        os.environ['TEST_ARTIFACTS_DIR'] = artifacts_dir
        os.environ['TEST_MAX_WORKERS'] = str(config['max_workers'])
        os.environ['TEST_TIMEOUT'] = str(config['test_timeout'])
        
        return config


def install_test_dependencies():
    """Install test dependencies"""
    dependencies = [
        'pytest>=7.0.0',
        'pytest-asyncio>=0.20.0',
        'pytest-cov>=4.0.0',
        'pytest-html>=3.0.0',
        'pytest-xdist>=3.0.0',
        'pytest-timeout>=2.0.0',
        'psutil>=5.8.0'
    ]
    
    print("Installing test dependencies...")
    for dep in dependencies:
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', dep], 
                         check=True, capture_output=True)
            print(f"✅ Installed {dep}")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install {dep}: {e}")
            return False
    
    return True


def run_ci_tests():
    """Run tests in CI environment"""
    config = CIConfig.setup_environment()
    
    # Install dependencies
    if not install_test_dependencies():
        sys.exit(1)
    
    # Build test command
    cmd = [
        sys.executable, '-m', 'pytest',
        'tests/',
        f'--maxfail=5',
        f'--timeout={config["test_timeout"]}',
        f'-n {config["max_workers"]}',
        '--tb=short',
        '--strict-markers'
    ]
    
    # Add coverage if configured
    if config.get('coverage_threshold'):
        cmd.extend([
            '--cov=src',
            '--cov-report=html:test_artifacts/coverage',
            '--cov-report=xml:test_artifacts/coverage.xml',
            '--cov-report=term',
            f'--cov-fail-under={config["coverage_threshold"]}'
        ])
    
    # Add report formats
    if 'junit' in config['report_format']:
        cmd.append('--junit-xml=test_artifacts/junit.xml')
    
    if 'html' in config['report_format']:
        cmd.extend([
            '--html=test_artifacts/report.html',
            '--self-contained-html'
        ])
    
    # Add performance tests if enabled
    if not config['performance_tests']:
        cmd.append('-m not performance')
    
    # Run tests
    print(f"Running tests with command: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=Path(__file__).parent)
    
    return result.returncode


def generate_ci_report():
    """Generate CI-specific test report"""
    config = CIConfig.get_test_config()
    env = CIConfig.detect_ci_environment()
    
    report = {
        'environment': env,
        'timestamp': subprocess.run(
            ['date', '-u', '+%Y-%m-%dT%H:%M:%SZ'],
            capture_output=True, text=True
        ).stdout.strip(),
        'config': config,
        'artifacts': []
    }
    
    # List available artifacts
    artifacts_dir = config['artifacts_dir']
    if os.path.exists(artifacts_dir):
        for file in os.listdir(artifacts_dir):
            if file.endswith(('.xml', '.html', '.json')):
                report['artifacts'].append({
                    'name': file,
                    'path': os.path.join(artifacts_dir, file),
                    'size': os.path.getsize(os.path.join(artifacts_dir, file))
                })
    
    # Save report
    report_path = os.path.join(artifacts_dir, 'ci_report.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"CI report saved to: {report_path}")
    return report


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="CI Test Runner")
    parser.add_argument('action', choices=['setup', 'test', 'report'], 
                       help='Action to perform')
    
    args = parser.parse_args()
    
    if args.action == 'setup':
        config = CIConfig.setup_environment()
        print(f"Environment setup complete: {config}")
        
    elif args.action == 'test':
        exit_code = run_ci_tests()
        sys.exit(exit_code)
        
    elif args.action == 'report':
        report = generate_ci_report()
        print(f"Report generated: {json.dumps(report, indent=2)}")
