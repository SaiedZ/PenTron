"""Standalone report exporter — run with: python -m pentron.export"""

from ..db import get_all_history, get_session
from .menu import export_menu


def main():
    print("\n\033[91m    PENTRON — Standalone Report Exporter\033[0m")
    print("\033[90m    ─────────────────────────────────────\033[0m\n")

    rows = get_all_history()
    if not rows:
        print("[!] No sessions found in database.")
        return

    print(f"{'SL#':<6} {'TARGET':<28} {'DATE':<22} {'STATUS'}")
    print("─" * 65)
    for row in rows:
        print(f"{row[0]:<6} {row[1]:<28} {str(row[2]):<22} {row[3]}")
    print()

    sl_input = input("\033[36mEnter SL# to export: \033[0m").strip()
    if not sl_input.isdigit():
        print("[!] Invalid SL#.")
        return

    data = get_session(int(sl_input))
    if not data["history"]:
        print(f"[!] SL# {sl_input} not found.")
        return

    export_menu(data)


if __name__ == "__main__":
    main()
