#!/usr/bin/env python3
"""
HBVM Agent CLI Entry Point
"""
import argparse
import sys
import json
from .agent import HBVMAgent
from .config import config


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='HBVM Agent - Host-Based Vulnerability Management Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m agent                    # Run agent daemon
  python -m agent --scan             # Run single scan
  python -m agent --status           # Show agent status
  python -m agent --test-connection  # Test backend connectivity
        """
    )
    
    parser.add_argument(
        '--scan',
        action='store_true',
        help='Run a single vulnerability scan and exit'
    )
    
    parser.add_argument(
        '--status',
        action='store_true',
        help='Show agent status and exit'
    )
    
    parser.add_argument(
        '--test-connection',
        action='store_true',
        help='Test connection to backend and exit'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='HBVM Agent 1.0.0'
    )
    
    args = parser.parse_args()
    
    # Override log level if verbose
    if args.verbose:
        config.log_level = 'DEBUG'
    
    # Create agent instance
    agent = HBVMAgent()
    
    try:
        if args.scan:
            # Run single scan
            print("Running vulnerability scan...")
            results = agent.run_single_scan()
            print(json.dumps(results, indent=2))
            
        elif args.status:
            # Show status
            status = agent.get_status()
            print(json.dumps(status, indent=2))
            
        elif args.test_connection:
            # Test backend connection
            print("Testing backend connection...")
            if agent.communicator.check_backend_health():
                print("✓ Backend is accessible")
                sys.exit(0)
            else:
                print("✗ Backend is not accessible")
                sys.exit(1)
                
        else:
            # Run daemon
            print("Starting HBVM Agent daemon...")
            agent.run()
            
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()