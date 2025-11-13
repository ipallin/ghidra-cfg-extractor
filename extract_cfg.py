#!/usr/bin/env python3
"""Utility to export control-flow graphs from binaries using Ghidra headless."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, List
import zipfile
from typing import Tuple


# Require Python 3.10+ because the code uses the PEP 604 union syntax (e.g. "Path | None").
if sys.version_info < (3, 10):
    sys.exit(
        "extract_cfg.py requires Python 3.10 or newer. "
        "'from __future__ import annotations' does not enable the `X | Y` "
        "annotation syntax on older Python versions.\n"
        f"Detected Python {sys.version_info.major}.{sys.version_info.minor}"
    )


def _default_ghidra_install() -> Path | None:
    env_value = os.environ.get("GHIDRA_INSTALL_DIR")
    if not env_value:
        return None
    return Path(env_value).expanduser().resolve()


def _resolve_headless_executable(ghidra_install: Path) -> Path:
    candidate = ghidra_install / "support" / "analyzeHeadless"
    if candidate.is_file():
        return candidate

    # Windows installs append .bat
    candidate_with_ext = candidate.with_suffix(candidate.suffix + ".bat")
    if candidate_with_ext.is_file():
        return candidate_with_ext

    raise FileNotFoundError(
        "Could not locate analyzeHeadless under {}".format(ghidra_install)
    )


def _validate_binaries(binaries: Iterable[Path]) -> List[Path]:
    resolved = []
    for binary in binaries:
        binary_path = binary.expanduser().resolve()
        if not binary_path.exists():
            raise FileNotFoundError(f"Binary '{binary}' does not exist")
        resolved.append(binary_path)
    return resolved


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Export per-function control-flow graphs from binaries using the "
            "Ghidra headless analyzer."
        )
    )
    parser.add_argument(
        "binaries",
        nargs="*",
        help=(
            "Path(s) to the compiled binaries that should be analyzed."
            " Optional when using --input-dir."
        ),
        type=Path,
    )
    parser.add_argument(
        "--input-dir",
        dest="input_dir",
        type=Path,
        help=(
            "Directory containing input files. Files may be raw binaries or"
            " zipped archives (.zip). Zipped archives will be extracted into"
            " a temporary directory and their contents processed."
        ),
    )
    parser.add_argument(
        "--ghidra-install",
        dest="ghidra_install",
        type=Path,
        default=_default_ghidra_install(),
        help=(
            "Directory where Ghidra is installed. Defaults to the value of "
            "the GHIDRA_INSTALL_DIR environment variable."
        ),
    )
    parser.add_argument(
        "--output-dir",
        dest="output_dir",
        type=Path,
        default=Path("cfg-output"),
        help="Directory where the CFG export files will be stored.",
    )
    parser.add_argument(
        "--keep-project",
        dest="keep_project",
        action="store_true",
        help=(
            "Keep the temporary Ghidra project directories. Useful for "
            "debugging but disabled by default."
        ),
    )
    parser.add_argument(
        "--overwrite",
        dest="overwrite",
        action="store_true",
        help="Overwrite output files if they already exist.",
    )
    parser.add_argument(
        "--script",
        dest="script",
        type=Path,
        default=Path(__file__).with_name("ghidra_scripts") / "export_cfg.py",
        help=(
            "Path to the Ghidra post-script that performs the CFG export. "
            "Defaults to the script that ships with this repository."
        ),
    )
    parser.add_argument(
        "--language-id",
        dest="language_id",
        help=(
            "Override the processor/language that Ghidra should use when "
            "importing the binary (e.g. 'x86:LE:32:default')."
        ),
    )
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=("json", "graphml"),
        default="graphml",
        help="Format of the exported control-flow graphs. Defaults to graphml.",
    )
    parser.add_argument(
        "--entry-address",
        dest="entry_address",
        help=(
            "Optional address for the entry function to export when the loader "
            "cannot resolve main automatically (e.g. 0x401000)."
        ),
    )
    parser.add_argument(
        "--zip-password",
        dest="zip_password",
        action="append",
        help=(
            "Password to try when extracting encrypted ZIP archives. Can be passed "
            "multiple times to try multiple passwords in order. The default 'infected' "
            "will still be attempted if no password succeeds."
        ),
    )
    return parser


def _build_analyze_command(
    analyze_headless: Path,
    project_dir: Path,
    project_name: str,
    binary: Path,
    script_path: Path,
    output_path: Path,
    output_format: str,
    language_id: str | None = None,
    entry_address: str | None = None,
) -> List[str]:
    command = [
        str(analyze_headless),
        str(project_dir),
        project_name,
        "-import",
        str(binary),
    ]

    if language_id:
        command.extend(["-processor", language_id])

    command.extend(
        [
            "-scriptPath",
            str(script_path.parent),
            "-postScript",
            script_path.name,
            str(output_path),
            output_format,
        ]
    )

    if entry_address:
        command.append(entry_address)

    return command


def run_analysis(
    binaries: List[Path],
    ghidra_install: Path,
    output_dir: Path,
    script_path: Path,
    output_format: str,
    keep_project: bool = False,
    overwrite: bool = False,
    language_id: str | None = None,
    entry_address: str | None = None,
) -> None:
    if not ghidra_install:
        raise ValueError(
            "The path to the Ghidra installation is required. Use --ghidra-install "
            "or set GHIDRA_INSTALL_DIR."
        )
    ghidra_install = ghidra_install.expanduser().resolve()
    if not ghidra_install.exists():
        raise FileNotFoundError(f"Ghidra installation not found at {ghidra_install}")

    analyze_headless = _resolve_headless_executable(ghidra_install)

    script_path = script_path.expanduser().resolve()
    if not script_path.exists():
        raise FileNotFoundError(f"Ghidra script not found at {script_path}")

    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    for binary in binaries:
        output_path = output_dir / (binary.name + ".cfg." + output_format)
        if output_path.exists() and not overwrite:
            raise FileExistsError(
                f"Output file {output_path} already exists. Use --overwrite to replace it."
            )

    for binary in binaries:
        project_dir = Path(tempfile.mkdtemp(prefix="ghidra_cfg_"))
        project_name = binary.stem
        output_path = output_dir / (binary.name + ".cfg." + output_format)

        command = _build_analyze_command(
            analyze_headless=analyze_headless,
            project_dir=project_dir,
            project_name=project_name,
            binary=binary,
            script_path=script_path,
            output_path=output_path,
            output_format=output_format,
            language_id=language_id,
            entry_address=entry_address,
        )

        print("[+] Running:", " ".join(command))
        try:
            subprocess.run(command, check=True)
            print(f"[+] CFG exported to {output_path}")
        finally:
            if keep_project:
                print(f"[!] Preserving temporary project at {project_dir}")
            else:
                shutil.rmtree(project_dir, ignore_errors=True)


def _gather_from_input_dir(input_dir: Path, zip_passwords: list[str] | None = None) -> Tuple[List[Path], List[Path]]:
    """Collect binaries from `input_dir`.

    Returns a tuple (binaries, temp_dirs) where `temp_dirs` are any temporary
    directories created when extracting archives and should be cleaned up by
    the caller when appropriate.
    """
    input_dir = input_dir.expanduser().resolve()
    if not input_dir.exists() or not input_dir.is_dir():
        raise FileNotFoundError(f"Input directory not found: {input_dir}")

    collected: List[Path] = []
    temp_dirs: List[Path] = []

    for entry in input_dir.iterdir():
        if not entry.is_file():
            # Skip subdirectories; keep behavior simple. Users can place only
            # files directly in the input directory.
            continue

        if entry.suffix.lower() == ".zip":
            td = Path(tempfile.mkdtemp(prefix="gh_extract_"))
            try:
                with zipfile.ZipFile(entry, "r") as zf:
                    try:
                        zf.extractall(td)
                    except RuntimeError as re:
                        # zipfile raises RuntimeError when files are encrypted
                        # and no password was provided.
                        msg = str(re).lower()
                        if "encrypted" in msg or "password" in msg:
                            # Build ordered list of passwords to try: user-provided first, then default
                            passwords: list[str] = list(zip_passwords or [])
                            if "infected" not in passwords:
                                passwords.append("infected")

                            extracted = False
                            # Try stdlib with each password
                            for pw in passwords:
                                try:
                                    print(f"[i] Archive appears encrypted; trying password '{pw}' with stdlib for {entry}")
                                    zf.extractall(td, pwd=pw.encode())
                                    extracted = True
                                    break
                                except RuntimeError:
                                    continue

                            if not extracted:
                                # Prefer p7zip (7z/7za/7zr) which supports AES-encrypted zips
                                for sevenz_cmd in ("7z", "7za", "7zr"):
                                    sevenz_bin = shutil.which(sevenz_cmd)
                                    if not sevenz_bin:
                                        continue
                                    for pw in passwords:
                                        print(f"[i] attempting '{sevenz_cmd}' with password '{pw}' for {entry}")
                                        # 7z x -pPASSWORD -y -oDEST ARCHIVE
                                        cmd = [sevenz_bin, "x", f"-p{pw}", "-y", f"-o{str(td)}", str(entry)]
                                        res = subprocess.run(
                                            cmd,
                                            check=False,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE,
                                            text=True,
                                        )
                                        if res.returncode == 0:
                                            extracted = True
                                            break
                                        else:
                                            print(f"[!] {sevenz_cmd} failed for {entry}: {res.stderr.strip()}")
                                    if extracted:
                                        break

                                # If p7zip couldn't handle it, try system unzip (may not support newer PK compat/encryption)
                                if not extracted:
                                    unzip_bin = shutil.which("unzip")
                                    if unzip_bin:
                                        for pw in passwords:
                                            print(f"[i] p7zip/unzip attempt failed; attempting system 'unzip' with password '{pw}' for {entry}")
                                            res = subprocess.run(
                                                [unzip_bin, "-P", pw, "-o", str(entry), "-d", str(td)],
                                                check=False,
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.PIPE,
                                                text=True,
                                            )
                                            if res.returncode == 0:
                                                extracted = True
                                                break
                                            else:
                                                print(f"[!] system unzip failed for {entry}: {res.stderr.strip()}")

                            if not extracted:
                                raise RuntimeError("could not extract encrypted archive with available passwords/tools")
                        else:
                            raise
            except zipfile.BadZipFile:
                print(f"[!] Skipping invalid zip archive: {entry}")
                shutil.rmtree(td, ignore_errors=True)
                continue
            except Exception:
                # Any failure extracting (bad zip, wrong password, missing unzip, etc.) -> skip archive
                print(f"[!] Skipping archive due to extraction failure: {entry}")
                shutil.rmtree(td, ignore_errors=True)
                continue

            # collect all files extracted
            for p in td.rglob("*"):
                if p.is_file():
                    collected.append(p)

            temp_dirs.append(td)
        else:
            collected.append(entry.resolve())

    return collected, temp_dirs


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    temp_dirs: List[Path] = []

    binaries_to_process: List[Path] = []

    # Gather binaries either from positional args, or from --input-dir, or both.
    if args.input_dir:
        try:
            gathered, temp_dirs = _gather_from_input_dir(args.input_dir, args.zip_password)
        except FileNotFoundError as exc:
            parser.error(str(exc))
            return 2

        # extend with any explicitly provided positional binaries
        binaries_to_process.extend(gathered)

    if args.binaries:
        binaries_to_process.extend(args.binaries)

    if not binaries_to_process:
        parser.error("No binaries provided. Pass paths or use --input-dir.")
        return 2

    try:
        binaries = _validate_binaries(binaries_to_process)
    except FileNotFoundError as exc:
        parser.error(str(exc))
        return 2

    try:
        run_analysis(
            binaries=binaries,
            ghidra_install=args.ghidra_install,
            output_dir=args.output_dir,
            script_path=args.script,
            output_format=args.output_format,
            keep_project=args.keep_project,
            overwrite=args.overwrite,
            language_id=args.language_id,
            entry_address=args.entry_address,
        )
    except (FileNotFoundError, ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
        return 2
    finally:
        # clean up any temporary extraction dirs unless user asked to keep
        if temp_dirs and not args.keep_project:
            for td in temp_dirs:
                shutil.rmtree(td, ignore_errors=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
