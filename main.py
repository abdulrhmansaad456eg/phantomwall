import os
import sys
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from web.app import create_app
from web.simulated_backend import sim_backend
from utils.config import ConfigManager


def main():
    parser = argparse.ArgumentParser(
        description="PhantomWall WAF - Educational Web Application Firewall",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    # Run with default settings
  python main.py --port 9000        # Run on custom port
  python main.py --host 0.0.0.0     # Allow external connections
  python main.py --config custom.json  # Use custom config file
        """
    )
    
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1)"
    )
    
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to listen on (default: 8080)"
    )
    
    parser.add_argument(
        "--config",
        default="phantomwall.json",
        help="Path to configuration file (default: phantomwall.json)"
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode"
    )
    
    args = parser.parse_args()
    
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║     ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗██╗    ██╗ ║
    ║     ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██║    ██║ ║
    ║     ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║ █╗ ██║ ║
    ║     ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║███╗██║ ║
    ║     ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚███╔███╔╝ ║
    ║     ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚══╝╚══╝  ║
    ║                                                           ║
    ║         Web Application Firewall Educational Prototype    ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    cfg = ConfigManager(args.config)
    
    if not os.path.exists(args.config):
        print(f"[INFO] Created default configuration: {args.config}")
    
    cfg.update({
        "host": args.host,
        "port": args.port
    })
    
    app = create_app(args.config)
    app.register_blueprint(sim_backend)
    
    print(f"[INFO] Configuration loaded from: {args.config}")
    print(f"[INFO] WAF Enabled: {cfg.get('enabled')}")
    print(f"[INFO] Blocking Mode: {cfg.get('blocking_mode')}")
    print(f"[INFO] Sensitivity: {cfg.get('sensitivity')}")
    print(f"[INFO] Rate Limit: {cfg.get('rate_limit')} req/min")
    print(f"[INFO] Language: {cfg.get('language')}")
    print()
    print(f"[STARTING] PhantomWall WAF Dashboard:")
    print(f"   URL: http://{args.host}:{args.port}")
    print(f"   Simulated Backend: http://{args.host}:{args.port}/backend")
    print()
    print("[TIP] Use the /test page to try different attack patterns")
    print("[TIP] Check /backend for simulated vulnerable endpoints")
    print()
    
    try:
        app.run(
            host=args.host,
            port=args.port,
            debug=args.debug,
            threaded=True
        )
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down PhantomWall...")
        sys.exit(0)


if __name__ == "__main__":
    main()
