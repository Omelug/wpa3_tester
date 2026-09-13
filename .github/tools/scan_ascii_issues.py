#!/usr/bin/env python3
"""
Scan a project tree for:
  1) Non-ASCII characters in text files.
  2) Lines that look empty but contain whitespace other than plain spaces/tabs (e.g. NBSP \\xa0, vertical tab, form feed,
     stray \\r, Unicode space separators).

Usage:
    python3 scan_ascii_issues.py [root_dir] [--ext .cpp .h .cmake ...]

If no --ext is given, it scans common CMake/C/C++ project file types plus CMakeLists.txt
Use --ext all to scan every non-binary file
"""
import argparse
import subprocess
import sys
from pathlib import Path

DEFAULT_EXTS = {
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx", ".hh", ".inl",
    ".cmake", ".txt", ".md", ".py", ".sh", ".yml", ".yaml", ".json",
}


def is_cmake_related(path: Path) -> bool:
    return path.name == "CMakeLists.txt" or path.suffix == ".cmake"


def should_scan(path: Path, exts) -> bool:
    if exts == {"all"}:
        return True
    return path.suffix in exts or is_cmake_related(path)


def iter_files(root: Path, exts):
    result = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True)
    for rel in result.stdout.splitlines():
        path = root / rel
        if should_scan(path, exts):
            yield path


def check_file(path: Path):
    issues = []
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        issues.append((0, "FILE NOT VALID UTF-8 (binary or other encoding)", ""))
        return issues
    except OSError as e:
        issues.append((0, f"COULD NOT READ FILE: {e}", ""))
        return issues

    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        # 1) Non-ASCII characters
        non_ascii = [ch for ch in raw_line if ord(ch) > 127]
        if non_ascii:
            codepoints = ", ".join(f"U+{ord(c):04X}" for c in sorted(set(non_ascii)))
            issues.append((lineno, "NON-ASCII", f"chars: {codepoints}"))

        # 2) Awkward blank lines: whitespace-only, but not just spaces/tabs
        if raw_line != "" and raw_line.strip() == "":
            if any(ch not in (" ", "\t") for ch in raw_line):
                codepoints = ", ".join(f"U+{ord(c):04X}" for c in sorted(set(raw_line)))
                issues.append((lineno, "AWKWARD BLANK LINE", f"chars: {codepoints}"))

    return issues


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", help="Project root (default: .)")
    parser.add_argument(
        "--ext", nargs="+", default=None,
        help="File extensions to scan (e.g. .cpp .h), or 'all' for every text file.",
    )
    args = parser.parse_args()

    exts = set(args.ext) if args.ext else DEFAULT_EXTS
    root = Path(args.root).resolve()

    total_issues = 0
    for path in sorted(iter_files(root, exts)):
        issues = check_file(path)
        if issues:
            rel = path.relative_to(root)
            for lineno, kind, detail in issues:
                total_issues += 1
                print(f"{rel}:{lineno}: [{kind}] {detail}")

    if total_issues == 0:
        print("No issues found.")
    else:
        print(f"\n{total_issues} issue(s) found.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

