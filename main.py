"""SecureShield Firewall - main entrypoint."""
import argparse
import sys

import config


def main():
    parser = argparse.ArgumentParser(
        description="SecureShield Hybrid Firewall",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    # Start dashboard (default)
  python main.py --mode dashboard   # Start dashboard explicitly
  python main.py --mode train       # Train ML model
  python main.py --port 8080        # Start on custom port
        """
    )
    parser.add_argument(
        "--mode",
        default="dashboard",
        choices=["dashboard", "train"],
        help="Run mode (default: dashboard)"
    )
    parser.add_argument(
        "--host",
        default=config.DASHBOARD_HOST,
        help=f"Dashboard host (default: {config.DASHBOARD_HOST})"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=config.DASHBOARD_PORT,
        help=f"Dashboard port (default: {config.DASHBOARD_PORT})"
    )
    args = parser.parse_args()

    if args.mode == "train":
        print("=" * 60)
        print("  SecureShield - ML Training")
        print("=" * 60)
        from ml.train import train
        train()
        print("=" * 60)

    elif args.mode == "dashboard":
        print("=" * 60)
        print("  SecureShield Firewall - Dashboard Mode")
        print("=" * 60)
        print(f"  Dashboard URL: http://{args.host}:{args.port}")
        print(f"  Press Ctrl+C to stop")
        print("=" * 60)
        from firewall.dashboard.app import run as run_dashboard
        try:
            run_dashboard(args.host, args.port)
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
            sys.exit(0)


if __name__ == "__main__":
    main()
