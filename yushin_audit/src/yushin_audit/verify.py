"""CLI entry point: python -m yushin_audit.verify path/to/audit.jsonl"""
import sys
from . import AuditLogger


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m yushin_audit.verify <audit.jsonl>", file=sys.stderr)
        return 2
    ok, msg = AuditLogger.verify(sys.argv[1])
    print(msg)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
