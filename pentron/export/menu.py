"""Interactive export menu — CLI-only (print/input), called from pentron/cli.py."""

import os

from .html import export_html
from .pdf import export_pdf


def export_menu(data: dict):
    if not data["history"]:
        print("[!] No session data to export.")
        return

    h = data["history"]
    sl = h[0]
    tgt = h[1]

    print(f"\n\033[33m{'─' * 20} EXPORT SL#{sl} — {tgt} {'─' * 20}\033[0m")
    print("  [1] PDF report")
    print("  [2] HTML report")
    print("  [3] Both")
    print("  [4] Back")
    print(f"\033[90m{'─' * 60}\033[0m")

    choice = input("\033[36mExport format: \033[0m").strip()
    output_dir = os.path.expanduser("~/PenTron/reports")
    os.makedirs(output_dir, exist_ok=True)

    if choice == "1":
        p = export_pdf(data, output_dir)
        print(f"\033[92m[+] PDF saved: {p}\033[0m")
    elif choice == "2":
        p = export_html(data, output_dir)
        print(f"\033[92m[+] HTML saved: {p}\033[0m")
    elif choice == "3":
        p1 = export_pdf(data, output_dir)
        p2 = export_html(data, output_dir)
        print(f"\033[92m[+] PDF  : {p1}\033[0m")
        print(f"\033[92m[+] HTML : {p2}\033[0m")
    elif choice == "4":
        return
    else:
        print("\033[93m[!] Invalid choice.\033[0m")
