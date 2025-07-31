#!/usr/bin/env python3
"""
Test script for the Vulnerability Scanner Agent
Verifies functionality of all scanner components
"""

import os
import sys
import json
import time
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

# Add the current directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vulnerability_scanner import (
    SystemInfoCollector,
    PackageCollector, 
    NetworkScanner,
    CVEMatcher,
    VulnerabilityScanner
)


class TestSystemInfoCollector(unittest.TestCase):
    """Test system information collection"""
    
    def setUp(self):
        self.collector = SystemInfoCollector()
    
    def test_get_system_info(self):
        """Test system info collection"""
        info = self.collector.get_system_info()
        
        # Verify required fields are present
        required_fields = [
            'hostname', 'platform', 'system', 'release', 
            'version', 'machine', 'cpu_count', 'memory_total', 
            'timestamp'
        ]
        
        for field in required_fields:
            self.assertIn(field, info, f"Missing required field: {field}")
        
        # Verify data types
        self.assertIsInstance(info['cpu_count'], int)
        self.assertIsInstance(info['memory_total'], int)
        self.assertIsInstance(info['disk_usage'], dict)
        self.assertIsInstance(info['network_interfaces'], list)
        
        print("✅ System info collection test passed")


class TestPackageCollector(unittest.TestCase):
    """Test package collection functionality"""
    
    def setUp(self):
        self.collector = PackageCollector()
    
    def test_get_installed_packages(self):
        """Test package collection"""
        packages = self.collector.get_installed_packages()
        
        # Should return a list
        self.assertIsInstance(packages, list)
        
        # If packages found, verify structure
        if packages:
            package = packages[0]
            required_fields = ['name', 'version', 'package_manager']
            
            for field in required_fields:
                self.assertIn(field, package, f"Missing package field: {field}")
        
        print(f"✅ Package collection test passed ({len(packages)} packages found)")
    
    def test_parse_dpkg_output(self):
        """Test dpkg output parsing"""
        sample_output = """ii  adduser  3.118ubuntu5  all  add and remove users and groups
ii  apt  2.4.5  amd64  commandline package manager"""
        
        packages = self.collector._parse_dpkg_output(sample_output)
        
        self.assertEqual(len(packages), 2)
        self.assertEqual(packages[0]['name'], 'adduser')
        self.assertEqual(packages[0]['version'], '3.118ubuntu5')
        self.assertEqual(packages[0]['package_manager'], 'dpkg')
        
        print("✅ dpkg output parsing test passed")
    
    def test_parse_rpm_output(self):
        """Test rpm output parsing"""
        sample_output = """bash-5.1.8-4.el9.x86_64
coreutils-8.32-31.el9.x86_64"""
        
        packages = self.collector._parse_rpm_output(sample_output)
        
        self.assertEqual(len(packages), 2)
        self.assertEqual(packages[0]['name'], 'bash')
        self.assertEqual(packages[0]['version'], '5.1.8-4.el9.x86_64')
        self.assertEqual(packages[0]['package_manager'], 'rpm')
        
        print("✅ rpm output parsing test passed")


class TestNetworkScanner(unittest.TestCase):
    """Test network scanning functionality"""
    
    def setUp(self):
        self.scanner = NetworkScanner()
    
    def test_get_open_ports(self):
        """Test open port detection"""
        ports = self.scanner.get_open_ports()
        
        # Should return a list
        self.assertIsInstance(ports, list)
        
        # If ports found, verify structure
        if ports:
            port = ports[0]
            required_fields = ['port', 'protocol', 'address']
            
            for field in required_fields:
                self.assertIn(field, port, f"Missing port field: {field}")
            
            # Verify port number is valid
            self.assertIsInstance(port['port'], int)
            self.assertGreater(port['port'], 0)
            self.assertLessEqual(port['port'], 65535)
        
        print(f"✅ Network scanning test passed ({len(ports)} open ports found)")
    
    def test_get_running_processes(self):
        """Test running process detection"""
        processes = self.scanner.get_running_processes()
        
        # Should return a list
        self.assertIsInstance(processes, list)
        
        # Should find at least some processes
        self.assertGreater(len(processes), 0, "No processes found")
        
        # Verify process structure
        process = processes[0]
        required_fields = ['pid', 'name']
        
        for field in required_fields:
            self.assertIn(field, process, f"Missing process field: {field}")
        
        print(f"✅ Process scanning test passed ({len(processes)} processes found)")


class TestCVEMatcher(unittest.TestCase):
    """Test CVE matching functionality"""
    
    def setUp(self):
        config = {
            'vulners_api_key': '',
            'enable_cve_matching': True,
            'timeout_seconds': 10
        }
        self.matcher = CVEMatcher(config)
    
    @patch('requests.Session.post')
    def test_query_vulners_api(self, mock_post):
        """Test Vulners API query with mocked response"""
        # Mock successful API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'result': 'OK',
            'data': {
                'search': [
                    {
                        '_id': 'CVE-2023-1234',
                        'title': 'Test vulnerability',
                        'description': 'Test description',
                        'cvss': {'score': 7.5},
                        'published': '2023-01-01',
                        'references': []
                    }
                ]
            }
        }
        mock_post.return_value = mock_response
        
        vulnerabilities = self.matcher._query_vulners_api('openssl', '1.1.1f')
        
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0]['cve_id'], 'CVE-2023-1234')
        self.assertEqual(vulnerabilities[0]['severity'], 'high')
        
        print("✅ CVE API query test passed")
    
    def test_get_severity(self):
        """Test CVSS score to severity conversion"""
        test_cases = [
            (9.5, 'critical'),
            (7.5, 'high'),
            (5.0, 'medium'),
            (2.0, 'low'),
            (None, 'unknown')
        ]
        
        for score, expected_severity in test_cases:
            severity = self.matcher._get_severity(score)
            self.assertEqual(severity, expected_severity)
        
        print("✅ Severity calculation test passed")


class TestVulnerabilityScanner(unittest.TestCase):
    """Test main scanner functionality"""
    
    def setUp(self):
        # Create temporary config file
        self.temp_config = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        config_data = {
            'scan_interval': 3600,
            'api_endpoint': 'http://localhost:8080/test',
            'log_level': 'INFO',
            'enable_cve_matching': False,  # Disable for testing
            'max_packages_to_scan': 5
        }
        json.dump(config_data, self.temp_config)
        self.temp_config.close()
        
        self.scanner = VulnerabilityScanner(self.temp_config.name)
    
    def tearDown(self):
        # Clean up temporary file
        os.unlink(self.temp_config.name)
    
    def test_load_config(self):
        """Test configuration loading"""
        self.assertIsInstance(self.scanner.config, dict)
        self.assertEqual(self.scanner.config['scan_interval'], 3600)
        self.assertEqual(self.scanner.config['enable_cve_matching'], False)
        
        print("✅ Configuration loading test passed")
    
    def test_scan(self):
        """Test complete scan functionality"""
        # Run a scan
        result = self.scanner.scan()
        
        # Verify result structure
        required_fields = [
            'scan_id', 'timestamp', 'system_info', 'packages',
            'open_ports', 'running_processes', 'vulnerabilities',
            'scan_duration', 'errors'
        ]
        
        for field in required_fields:
            self.assertIn(field, result, f"Missing result field: {field}")
        
        # Verify data types
        self.assertIsInstance(result['system_info'], dict)
        self.assertIsInstance(result['packages'], list)
        self.assertIsInstance(result['open_ports'], list)
        self.assertIsInstance(result['running_processes'], list)
        self.assertIsInstance(result['vulnerabilities'], list)
        self.assertIsInstance(result['scan_duration'], (int, float))
        self.assertIsInstance(result['errors'], list)
        
        print("✅ Full scan test passed")
        print(f"   - Found {len(result['packages'])} packages")
        print(f"   - Found {len(result['open_ports'])} open ports")
        print(f"   - Found {len(result['running_processes'])} processes")
        print(f"   - Scan duration: {result['scan_duration']:.2f} seconds")


def run_functional_test():
    """Run a functional test of the scanner"""
    print("\n🧪 Running functional test...")
    
    try:
        # Create a minimal config for testing
        test_config = {
            'scan_interval': 60,
            'log_level': 'INFO',
            'enable_cve_matching': False,
            'max_packages_to_scan': 10
        }
        
        # Write test config
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_config, f)
            config_file = f.name
        
        try:
            # Create scanner instance
            scanner = VulnerabilityScanner(config_file)
            
            # Run a single scan
            print("Running scan...")
            start_time = time.time()
            result = scanner.scan()
            duration = time.time() - start_time
            
            # Print summary
            print(f"\n📊 Scan Results Summary:")
            print(f"   Scan ID: {result['scan_id']}")
            print(f"   Duration: {duration:.2f} seconds")
            print(f"   System: {result['system_info'].get('platform', 'Unknown')}")
            print(f"   Packages: {len(result['packages'])}")
            print(f"   Open Ports: {len(result['open_ports'])}")
            print(f"   Processes: {len(result['running_processes'])}")
            print(f"   Vulnerabilities: {len(result['vulnerabilities'])}")
            print(f"   Errors: {len(result['errors'])}")
            
            # Show some sample data
            if result['packages']:
                print(f"\n📦 Sample packages:")
                for pkg in result['packages'][:3]:
                    print(f"   - {pkg['name']} ({pkg['version']}) [{pkg['package_manager']}]")
            
            if result['open_ports']:
                print(f"\n🔌 Sample open ports:")
                for port in result['open_ports'][:3]:
                    print(f"   - Port {port['port']}/{port['protocol']} on {port['address']}")
            
            # Save result to file
            output_file = f"test_scan_result_{int(time.time())}.json"
            with open(output_file, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            
            print(f"\n💾 Results saved to: {output_file}")
            print("✅ Functional test completed successfully!")
            
        finally:
            # Clean up config file
            os.unlink(config_file)
    
    except Exception as e:
        print(f"❌ Functional test failed: {e}")
        return False
    
    return True


def main():
    """Main test runner"""
    print("🔬 Vulnerability Scanner Test Suite")
    print("=" * 50)
    
    # Run unit tests
    print("\n📋 Running unit tests...")
    
    test_classes = [
        TestSystemInfoCollector,
        TestPackageCollector,
        TestNetworkScanner,
        TestCVEMatcher,
        TestVulnerabilityScanner
    ]
    
    total_tests = 0
    passed_tests = 0
    
    for test_class in test_classes:
        print(f"\n🧪 Testing {test_class.__name__}...")
        
        # Create test suite
        suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
        
        # Run tests
        result = unittest.TextTestRunner(verbosity=0, stream=open(os.devnull, 'w')).run(suite)
        
        total_tests += result.testsRun
        passed_tests += result.testsRun - len(result.failures) - len(result.errors)
        
        if result.failures:
            print(f"❌ {len(result.failures)} test(s) failed")
            for test, traceback in result.failures:
                print(f"   FAIL: {test}")
        
        if result.errors:
            print(f"❌ {len(result.errors)} test(s) had errors")
            for test, traceback in result.errors:
                print(f"   ERROR: {test}")
        
        if not result.failures and not result.errors:
            print(f"✅ All {result.testsRun} tests passed")
    
    # Run functional test
    functional_success = run_functional_test()
    
    # Print summary
    print("\n" + "=" * 50)
    print("📊 Test Summary:")
    print(f"   Unit tests: {passed_tests}/{total_tests} passed")
    print(f"   Functional test: {'✅ PASSED' if functional_success else '❌ FAILED'}")
    
    if passed_tests == total_tests and functional_success:
        print("\n🎉 All tests passed! Scanner is ready for deployment.")
        return 0
    else:
        print("\n⚠️  Some tests failed. Please review and fix issues before deployment.")
        return 1


if __name__ == '__main__':
    sys.exit(main())