import argparse
import json
from core.engine import ModuleEngine
from core.storage import StorageEngine
from core.scope import Scope
from core.audit import AuditLog

def main():
    parser = argparse.ArgumentParser(description="Modular Platform Orchestrator")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Command: list
    subparsers.add_parser("list", help="List all available modules")

    # Command: run
    run_parser = subparsers.add_parser("run", help="Execute a module against a target")
    run_parser.add_argument("-m", "--module", required=True, help="Module name to run")
    run_parser.add_argument("-t", "--target", required=True, help="Target address or URL")
    run_parser.add_argument("--db", default="results.db", help="Path to SQLite database")
    run_parser.add_argument("--audit-db", default="audit.sqlite",
                            help="Path to audit log database (every outbound request)")
    run_parser.add_argument("--cache-dir", default=".cache/http",
                            help="HTTP disk cache directory")
    run_parser.add_argument("--scope", default="scope.json",
                            help="Scope file (JSON: domains/cidrs/handles). Fail-closed: "
                                 "missing or empty scope refuses all network requests.")
    run_parser.add_argument("--allow-all", action="store_true",
                            help="LOUD escape hatch: skip scope enforcement entirely.")
    run_parser.add_argument("--set", action="append", default=[], metavar="key=value",
                            help="Module config, repeatable (e.g. --set cf_token=abc --set confirm=yes)")

    # Command: contracts
    contracts_parser = subparsers.add_parser(
        "contracts",
        help="Audit every module's hardened contract (alias, failure modes). "
             "Exits nonzero if any module is incomplete.")

    # Command: export
    export_parser = subparsers.add_parser("export", help="Export stored results to JSON")
    export_parser.add_argument("-o", "--output", default="export.json", help="Output JSON filename")
    export_parser.add_argument("--db", default="results.db", help="Path to SQLite database")

    args = parser.parse_args()

    if args.command == "list":
        engine = ModuleEngine(modules_package="modules")
        modules = engine.list_modules()
        print(f"\nAvailable Modules ({len(modules)}):")
        print("-" * 60)
        for m in modules:
            print(f"  Name:        {m['name']}")
            print(f"  Description: {m['description']}\n")

    elif args.command == "run":
        scope = None
        if args.allow_all:
            print("[!] --allow-all: scope enforcement DISABLED. Every host is reachable.")
        else:
            try:
                scope = Scope.from_file(args.scope)
            except (OSError, ValueError) as e:
                print(f"[!] cannot load scope file '{args.scope}': {e}")
                print("[!] refusing to run unscoped (use --allow-all to override loudly)")
                return
        audit = AuditLog(args.audit_db)
        engine = ModuleEngine(modules_package="modules", scope=scope, audit=audit,
                              cache_dir=args.cache_dir, allow_all=args.allow_all)
        storage = StorageEngine(db_path=args.db)
        config = {}
        for item in args.set:
            if "=" not in item:
                print(f"[!] ignoring bad --set '{item}' (need key=value)")
                continue
            k, v = item.split("=", 1)
            config[k.strip()] = v.strip()
        print(f"[*] Executing module '{args.module}' against '{args.target}'...")
        result = engine.execute_module(module_name=args.module, target=args.target, config=config)

        row_id = storage.save_result(result)
        n_findings = storage.save_findings(result, row_id)
        print(f"[+] Run Complete. Status: {result.status} (Saved Record ID: {row_id}, "
              f"Findings: {n_findings})")
        print(json.dumps(result.to_dict(), indent=2))

    elif args.command == "contracts":
        engine = ModuleEngine(modules_package="modules")
        report = engine.contract_report()
        bad = 0
        print(f"\nModule Contracts ({len(report)} modules):")
        print("-" * 70)
        for m in report:
            flag = "OK " if not m["contract_problems"] else "FAIL"
            if m["contract_problems"]:
                bad += 1
            auth = " [requires per-action authorization]" if m["requires_auth"] else ""
            print(f"  [{flag}] {m['name']} — \"{m['alias']}\"{auth}")
            if m["contract_problems"]:
                for p in m["contract_problems"]:
                    print(f"         ! {p}")
            if not m["failure_modes"]:
                print("         ! no failure modes declared")
        print(f"\n{len(report) - bad}/{len(report)} contracts complete.")
        if bad:
            print("[!] incomplete contracts fail the build — fix them before shipping.")
            raise SystemExit(1)

    elif args.command == "export":
        storage = StorageEngine(db_path=args.db)
        storage.export_json(output_file=args.output)
        print(f"[+] Database contents exported to {args.output}")

if __name__ == "__main__":
    main()
