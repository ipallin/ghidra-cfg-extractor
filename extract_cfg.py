#!/usr/bin/env python3
"""Utility to export control-flow graphs from binaries using Ghidra headless."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import signal
from pathlib import Path
from typing import Iterable, List
import zipfile
from typing import Tuple
import concurrent.futures


# Ghidra headless instances are memory- and CPU-intensive. Running too many in
# parallel can cause failures, so keep the cap intentionally low.
MAX_CONCURRENT_GHIDRA = 2


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


def _auto_detect_ghidra_install() -> Path | None:
    """Try to auto-detect a Ghidra install directory by walking up from this
    script's location and the current working directory, looking for
    'support/analyzeHeadless'. Returns the install path or None if not found."""
    candidates = []
    here = Path(__file__).resolve()
    candidates.extend(here.parents)
    candidates.extend(Path.cwd().resolve().parents)

    seen: set[Path] = set()
    for base in candidates:
        if base in seen:
            continue
        seen.add(base)
        support = base / "support"
        if (support / "analyzeHeadless").is_file() or (support / "analyzeHeadless.bat").is_file():
            return base
    return None


def _validate_binaries(binaries: Iterable[Path]) -> List[Path]:
    resolved = []
    for binary in binaries:
        binary_path = binary.expanduser().resolve()
        if not binary_path.exists():
            raise FileNotFoundError(f"Binary '{binary}' does not exist")
        resolved.append(binary_path)
    return resolved


def _is_likely_binary(path: Path) -> bool:
    """Heuristically determine if a file is a compiled binary we can feed to Ghidra.

    Recognizes ELF and PE (MZ) and Mach-O magic values. This is a light filter to
    avoid passing archives, text files, or other junk to analyzeHeadless.
    """
    try:
        with open(path, "rb") as f:
            header = f.read(4)
            if len(header) < 2:
                return False
            # ELF
            if header.startswith(b"\x7fELF"):
                return True
            # PE/COFF (Windows)
            if header.startswith(b"MZ"):
                return True
            # Mach-O (fat and thin)
            if len(header) == 4:
                magic = int.from_bytes(header, byteorder="big")
                if magic in {
                    0xFEEDFACE, 0xFEEDFACF,  # big-endian 32/64
                    0xCAFEBABE,              # fat binary (big-endian)
                }:
                    return True
                magic_le = int.from_bytes(header, byteorder="little")
                if magic_le in {0xCEFAEDFE, 0xCFFAEDFE}:
                    return True
    except Exception:
        # If we cannot read the file, treat it as not a valid binary for our purposes.
        return False
    return False


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
        choices=("json", "graphml", "gexf"),
        default="graphml",
        help="Format of the exported control-flow graphs. Defaults to graphml.",
    )
    parser.add_argument(
        "--jvm-arg",
        dest="jvm_arg",
        action="append",
        help=(
            "JVM argument to pass to analyzeHeadless. Can be repeated. "
            "Examples: -Xmx12G or -XX:ActiveProcessorCount=16. The wrapper "
            "will prefix with -J if needed."
        ),
    )
    parser.add_argument(
        "--auto-tune",
        dest="auto_tune",
        action="store_true",
        help=(
            "Automatically choose --workers and JVM heap/threads based on system resources. "
            "When enabled the script will compute a safe per-instance -Xmx, set ActiveProcessorCount "
            "and ParallelGCThreads, and adjust --workers to avoid OOM."
        ),
    )
    parser.add_argument(
        "--workers",
        dest="workers",
        type=int,
        default=_default_worker_count(),
        help=(
            "Number of concurrent analyses to run. Defaults to a small, safe level of"
            " parallelism (up to 2) to speed up processing without overwhelming Ghidra."
            " Set to 1 to run sequentially."
        ),
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
        "--all-functions",
        dest="all_functions",
        action="store_true",
        help=(
            "Export CFGs for all discovered functions in each binary instead of only 'main'."
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
    jvm_args: list[str] | None = None,
) -> List[str]:
    """Build the analyzeHeadless command.

    If `jvm_args` are provided they may be passed as e.g. "-Xmx12G" or
    "-J-XX:ActiveProcessorCount=16". The helper will normalize them to start
    with "-J" when constructing the command so the JVM receives them.
    """

    # Do not place -J/JVM args on the analyzeHeadless argv; instead the
    # subprocess environment will set JAVA_TOOL_OPTIONS if jvm_args are
    # provided. Putting -J options on the argv confuses analyzeHeadless
    # argument parsing.
    command: List[str] = [
        str(analyze_headless),
        str(project_dir),
        project_name,
        "-import",
        str(binary),
    ]

    if language_id:
        command.extend(["-processor", language_id])

    command.extend([
        "-scriptPath",
        str(script_path.parent),
        "-postScript",
        script_path.name,
        str(output_path),
        output_format,
    ])

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
    jvm_args: list[str] | None = None,
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
        _analyze_single(
            binary=binary,
            analyze_headless=analyze_headless,
            script_path=script_path,
            output_dir=output_dir,
            output_format=output_format,
            keep_project=keep_project,
            overwrite=overwrite,
            language_id=language_id,
            entry_address=entry_address,
            jvm_args=jvm_args,
        )


def _analyze_single(
    binary: Path,
    analyze_headless: Path,
    script_path: Path,
    output_dir: Path,
    output_format: str,
    keep_project: bool = False,
    overwrite: bool = False,
    language_id: str | None = None,
    entry_address: str | None = None,
    jvm_args: list[str] | None = None,
) -> None:
    """Analyze a single binary by invoking analyzeHeadless and manage the temp project dir.

    This helper is safe to call concurrently from multiple threads.
    """
    project_dir = Path(tempfile.mkdtemp(prefix="ghidra_cfg_"))
    project_name = binary.stem
    output_path = output_dir / (binary.name + ".cfg." + output_format)

    if output_path.exists() and not overwrite:
        raise FileExistsError(
            f"Output file {output_path} already exists. Use --overwrite to replace it."
        )

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
        jvm_args=jvm_args,
    )

    print("[+] Running:", " ".join(command))
    try:
        # If JVM args were provided, set them via JAVA_TOOL_OPTIONS so the
        # underlying java launcher receives them. We strip any leading -J
        # prefix the user may have supplied and join into a single string.
        env = os.environ.copy()
        if jvm_args:
            norm: List[str] = []
            for a in jvm_args:
                if a.startswith("-J"):
                    norm.append(a[2:])
                elif a.startswith("-"):
                    norm.append(a)
                else:
                    norm.append("-" + a)
            # Set both common env vars to be maximally compatible
            env_val = " ".join(norm)
            env["JAVA_TOOL_OPTIONS"] = env_val
            env["_JAVA_OPTIONS"] = env_val

        subprocess.run(command, check=True, env=env)
        if output_path.exists():
            print(f"[+] CFG exported to {output_path}")
        else:
            print(
                f"[!] No output produced for {binary}. The program may not have a 'main' function or export failed."
            )
    finally:
        if keep_project:
            print(f"[!] Preserving temporary project at {project_dir}")
        else:
            shutil.rmtree(project_dir, ignore_errors=True)
def _is_within_directory(directory: Path, target: Path) -> bool:
    """Return True if *target* resides inside *directory*."""

    try:
        target.relative_to(directory)
        return True
    except ValueError:
        return False


def _get_mem_available_mb() -> int:
    """Return available memory in MB using /proc/meminfo when possible.

    Falls back to 0 if it cannot determine.
    """
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    parts = line.split()
                    # value in kB
                    kb = int(parts[1])
                    return kb // 1024
            # If MemAvailable not present, try MemFree+Buffers+Cached
            f.seek(0)
            mem = {}
            for line in f:
                k = line.split()[0].rstrip(":")
                v = int(line.split()[1])
                mem[k] = v
            kb = mem.get("MemFree", 0) + mem.get("Buffers", 0) + mem.get("Cached", 0)
            return kb // 1024
    except Exception:
        return 0


def _default_worker_count() -> int:
    """Return a conservative default worker count.

    To avoid overloading the host or Ghidra, cap the default to a small number
    of concurrent instances while still enabling some parallelism when CPU
    cores are available.
    """

    cpu = os.cpu_count() or 1
    return max(1, min(cpu, MAX_CONCURRENT_GHIDRA))


def _clamp_workers(requested: int) -> int:
    """Clamp requested worker count to the supported maximum."""

    return max(1, min(requested, MAX_CONCURRENT_GHIDRA))


def _auto_tune_settings(requested_workers: int | None = None) -> tuple[int, list[str]]:
    """Compute (workers, jvm_args) based on system CPU count and available memory.

    Heuristic:
      - Reserve a small amount of RAM for the OS (min 1 GB or 10% of available).
      - Target minimum heap per instance = 2048 MB.
      - Determine workers = min(cpu_count, floor((mem_available - reserve) / min_heap))
      - If requested_workers explicitly provided (and >0), cap to that value.
      - Compute per-instance Xmx = floor((mem_available - reserve) / workers)
      - Compute ActiveProcessorCount = max(1, floor(cpu_count / workers))
      - Set ParallelGCThreads = max(1, floor(ActiveProcessorCount/2)).
    """
    cpu = os.cpu_count() or 1
    mem_mb = _get_mem_available_mb()

    # Reserve at least 1024 MB or 10% of memory, whichever is larger
    reserve_mb = max(1024, int(mem_mb * 0.1)) if mem_mb > 0 else 1024

    min_heap_mb = 2048

    # If memory unknown fallback to conservative defaults
    if mem_mb <= 0:
        workers = min(cpu, requested_workers or cpu)
        jvm_args = [f"-Xmx{min(8, max(1, cpu))}G", f"-XX:ActiveProcessorCount={max(1, cpu//workers)}"]
        return workers, jvm_args

    usable_mb = max(0, mem_mb - reserve_mb)
    # maximum workers limited by CPU and memory
    max_by_mem = usable_mb // min_heap_mb if min_heap_mb > 0 else cpu
    max_workers = max(1, min(cpu, max(1, max_by_mem)))

    workers = max_workers
    if requested_workers and requested_workers > 0:
        workers = min(requested_workers, max_workers)

    # Ensure at least 1 worker
    workers = max(1, workers)

    # per-instance heap (MB)
    per_instance_mb = max(256, usable_mb // workers) if usable_mb > 0 else min_heap_mb

    # Convert to G suffix when appropriate
    if per_instance_mb >= 1024:
        xmx_val = f"{per_instance_mb // 1024}G"
    else:
        xmx_val = f"{per_instance_mb}M"

    # Compute CPU allocation per instance
    apc = max(1, cpu // workers)
    pgt = max(1, apc // 2)

    jvm_args: list[str] = [f"-Xmx{xmx_val}", f"-XX:ActiveProcessorCount={apc}", f"-XX:ParallelGCThreads={pgt}"]

    return workers, jvm_args


def _ensure_empty_directory(path: Path) -> None:
    """Remove all contents from *path* while keeping the directory itself."""

    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)
        return

    for child in path.iterdir():
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        else:
            try:
                child.unlink()
            except FileNotFoundError:
                # Another process might have removed the file between iteration
                # and unlink; ignore such race conditions.
                continue


def _safe_extract_zip(zip_path: Path, destination: Path, password: bytes | None = None) -> None:
    """Extract *zip_path* into *destination* while preventing path traversal."""

    with zipfile.ZipFile(zip_path, "r") as archive:
        destination = destination.resolve()
        for info in archive.infolist():
            member_path = Path(info.filename)
            if member_path.is_absolute():
                raise RuntimeError(
                    f"Archive {zip_path} contains an absolute path entry: {info.filename}"
                )

            resolved_target = (destination / member_path).resolve()
            if not _is_within_directory(destination, resolved_target):
                raise RuntimeError(
                    f"Archive {zip_path} would extract outside the destination directory"
                )

        if password is None:
            archive.extractall(destination)
        else:
            archive.extractall(destination, pwd=password)


def _extract_zip_archive(entry: Path, zip_passwords: list[str] | None = None) -> Tuple[List[Path], List[Path]]:
    """Extract *entry* (a ZIP archive) and return collected files and temp dirs."""

    temp_dir = Path(tempfile.mkdtemp(prefix="gh_extract_"))
    passwords: list[str] = list(zip_passwords or [])
    if "infected" not in passwords:
        passwords.append("infected")

    try:
        try:
            _ensure_empty_directory(temp_dir)
            _safe_extract_zip(entry, temp_dir)
        except RuntimeError as exc:
            message = str(exc).lower()
            if "encrypted" not in message and "password" not in message:
                raise

            extracted = False
            for pw in passwords:
                _ensure_empty_directory(temp_dir)
                try:
                    print(
                        f"[i] Archive appears encrypted; trying password '{pw}' with stdlib for {entry}"
                    )
                    _safe_extract_zip(entry, temp_dir, password=pw.encode())
                    extracted = True
                    break
                except RuntimeError:
                    continue

            if not extracted:
                # Try p7zip (7z/7za/7zr) which supports AES-encrypted zips.
                for sevenz_cmd in ("7z", "7za", "7zr"):
                    sevenz_bin = shutil.which(sevenz_cmd)
                    if not sevenz_bin:
                        continue

                    for pw in passwords:
                        _ensure_empty_directory(temp_dir)
                        print(
                            f"[i] attempting '{sevenz_cmd}' with password '{pw}' for {entry}"
                        )
                        cmd = [
                            sevenz_bin,
                            "x",
                            f"-p{pw}",
                            "-y",
                            f"-o{str(temp_dir)}",
                            str(entry),
                        ]
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
                            print(
                                f"[!] {sevenz_cmd} failed for {entry}: {res.stderr.strip()}"
                            )
                    if extracted:
                        break

                if not extracted:
                    unzip_bin = shutil.which("unzip")
                    if unzip_bin:
                        for pw in passwords:
                            _ensure_empty_directory(temp_dir)
                            print(
                                "[i] p7zip/unzip attempt failed; attempting system 'unzip' "
                                f"with password '{pw}' for {entry}"
                            )
                            res = subprocess.run(
                                [
                                    unzip_bin,
                                    "-P",
                                    pw,
                                    "-o",
                                    str(entry),
                                    "-d",
                                    str(temp_dir),
                                ],
                                check=False,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True,
                            )
                            if res.returncode == 0:
                                extracted = True
                                break
                            else:
                                print(
                                    f"[!] system unzip failed for {entry}: {res.stderr.strip()}"
                                )

                if not extracted:
                    raise RuntimeError(
                        "could not extract encrypted archive with available passwords/tools"
                    )

        collected = [p for p in temp_dir.rglob("*") if p.is_file()]
        return collected, [temp_dir]
    except zipfile.BadZipFile:
        print(f"[!] Skipping invalid zip archive: {entry}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return [], []
    except Exception:
        print(f"[!] Skipping archive due to extraction failure: {entry}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return [], []


def _collect_from_path(path: Path, zip_passwords: list[str] | None = None) -> Tuple[List[Path], List[Path]]:
    """Collect binaries from *path* which may be a file or directory."""

    path = path.expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Input path not found: {path}")

    if path.is_dir():
        return _gather_from_input_dir(path, zip_passwords)

    if zipfile.is_zipfile(path):
        return _extract_zip_archive(path, zip_passwords)

    return [path], []


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

        if zipfile.is_zipfile(entry):
            files, temps = _extract_zip_archive(entry, zip_passwords)
            collected.extend(files)
            temp_dirs.extend(temps)
        else:
            collected.append(entry.resolve())

    return collected, temp_dirs


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # If no ghidra install specified or env-provided, attempt auto-detection
    if not args.ghidra_install:
        auto = _auto_detect_ghidra_install()
        if auto:
            print(f"[i] Auto-detected Ghidra installation at {auto}")
            args.ghidra_install = auto

    # Process per-entry without pre-extracting the entire input set.
    # Build a list of input entries (files only) without extracting upfront.
    entries: List[Path] = []
    if args.input_dir:
        input_dir = args.input_dir.expanduser().resolve()
        if not input_dir.exists() or not input_dir.is_dir():
            parser.error(f"Input directory not found: {input_dir}")
            return 2
        for entry in input_dir.iterdir():
            if entry.is_file():
                entries.append(entry)

    if args.binaries:
        for provided in args.binaries:
            p = provided.expanduser().resolve()
            if not p.exists():
                parser.error(f"Input path not found: {p}")
                return 2
            if p.is_dir():
                for entry in p.iterdir():
                    if entry.is_file():
                        entries.append(entry)
            else:
                entries.append(p)

    if not entries:
        parser.error("No input files found. Pass files or use --input-dir.")
        return 2

    # Track temps to ensure cleanup on interruption and normal exit
    remaining_temps: List[Path] = []

    def _handle_terminate(signum, frame):  # noqa: ARG001
        try:
            if not args.keep_project:
                for td in list(remaining_temps):
                    shutil.rmtree(td, ignore_errors=True)
        finally:
            code = 130 if signum == signal.SIGINT else 143
            os._exit(code)

    try:
        signal.signal(signal.SIGINT, _handle_terminate)
        signal.signal(signal.SIGTERM, _handle_terminate)
    except Exception:
        pass

    # Validate Ghidra installation and script once up-front so worker tasks don't
    # need to repeat the same checks.
    try:
        if not args.ghidra_install:
            raise ValueError(
                "The path to the Ghidra installation is required. Use --ghidra-install or set GHIDRA_INSTALL_DIR."
            )
        ghidra_install = args.ghidra_install.expanduser().resolve()
        if not ghidra_install.exists():
            parser.error(f"Ghidra installation not found at {ghidra_install}")
            return 2
        analyze_headless = _resolve_headless_executable(ghidra_install)

        script_path = args.script.expanduser().resolve()
        if not script_path.exists():
            parser.error(f"Ghidra script not found at {script_path}")
            return 2

        output_dir = args.output_dir.expanduser().resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
    except (ValueError, FileNotFoundError) as exc:
        parser.error(str(exc))
        return 2

    # Auto-tune workers and JVM args if requested.
    if args.auto_tune:
        requested = args.workers if hasattr(args, "workers") else None
        tuned_workers, tuned_jvm = _auto_tune_settings(requested_workers=requested)
        print(f"[i] Auto-tune: selected workers={tuned_workers}, jvm_args={tuned_jvm}")
        args.workers = tuned_workers
        # Merge tuned JVM args with any user-provided args, giving user args priority
        combined: list[str] = list(tuned_jvm)
        if args.jvm_arg:
            for a in args.jvm_arg:
                if a not in combined:
                    combined.append(a)
        args.jvm_arg = combined

    # If running sequentially (default) and the user didn't provide JVM args and
    # didn't request auto-tune, allocate most resources to the single Ghidra
    # instance so it can use all available CPUs and a large heap.
    if not args.auto_tune and args.workers == 1 and not args.jvm_arg:
        cpu = os.cpu_count() or 1
        mem_mb = _get_mem_available_mb()
        # Reserve 1 GB for the OS if possible
        reserve_mb = 1024
        if mem_mb and mem_mb > reserve_mb + 256:
            heap_mb = max(256, mem_mb - reserve_mb)
        elif mem_mb:
            heap_mb = max(128, mem_mb - 128)
        else:
            heap_mb = 2048

        if heap_mb >= 1024:
            xmx = f"{heap_mb // 1024}G"
        else:
            xmx = f"{heap_mb}M"

        apc = max(1, cpu)
        pgt = max(1, apc // 2)
        default_jvm = [f"-Xmx{xmx}", f"-XX:ActiveProcessorCount={apc}", f"-XX:ParallelGCThreads={pgt}"]
        args.jvm_arg = default_jvm
        print(f"[i] Default single-worker JVM args applied: {args.jvm_arg}")

    # Regardless of how the value was derived, cap concurrency to avoid running
    # too many Ghidra instances simultaneously.
    effective_workers = _clamp_workers(args.workers)
    if effective_workers != args.workers:
        print(
            f"[i] Reducing requested worker count from {args.workers} to {effective_workers}"
            f" to avoid running too many Ghidra instances at once (max {MAX_CONCURRENT_GHIDRA})."
        )
    args.workers = effective_workers

    # Create a worker pool to analyze binaries concurrently.
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=args.workers)
    futures: list[concurrent.futures.Future] = []

    # Per-entry processing: extract (if needed) -> validate -> submit analyze task(s)
    for entry in entries:
        try:
            if zipfile.is_zipfile(entry):
                collected, temps = _extract_zip_archive(entry, args.zip_password)
                remaining_temps.extend(temps)
                binaries = [p.resolve() for p in collected if _is_likely_binary(p)]
                print(f"[i] Extracted {len(binaries)} candidate binaries from {entry.name}")
            else:
                resolved = entry.resolve()
                binaries = [resolved] if _is_likely_binary(resolved) else []

            if not binaries:
                print(f"[i] Skipping {entry.name}: no valid binaries detected")
                continue

            try:
                validated = _validate_binaries(binaries)
            except FileNotFoundError as exc:
                print(f"[!] Skipping {entry.name}: {exc}")
                continue

            # Submit one task per validated binary. The helper will create its own
            # temporary project directory and clean it up when done (unless
            # --keep-project was passed).
            for vb in validated:
                fut = executor.submit(
                    _analyze_single,
                    vb,
                    analyze_headless,
                    script_path,
                    output_dir,
                    args.output_format,
                    args.keep_project,
                    args.overwrite,
                    args.language_id,
                    ("ALL" if args.all_functions else args.entry_address),
                    args.jvm_arg,
                )
                futures.append((entry, vb, fut))
        except (FileNotFoundError, ValueError, subprocess.CalledProcessError) as exc:
            parser.error(str(exc))
            return 2
        finally:
            # In concurrent mode, outputs may be produced after this entry loop,
            # so avoid premature warnings here. Errors will be surfaced when
            # awaiting task futures below.
            pass

    # Wait for all submitted tasks to finish and handle errors.
    executor.shutdown(wait=True)
    for entry, vb, fut in futures:
        try:
            fut.result()
        except subprocess.CalledProcessError as cpe:
            parser.error(f"Analysis failed for {vb}: {cpe}")
            return 2
        except Exception as exc:
            parser.error(str(exc))
            return 2

    # Clean up any temporary extraction directories now that analysis has finished.
    if not args.keep_project:
        for td in remaining_temps:
            shutil.rmtree(td, ignore_errors=True)

    return 0

if __name__ == "__main__":
    sys.exit(main())