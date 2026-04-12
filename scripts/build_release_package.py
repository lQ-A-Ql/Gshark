from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPO = "lQ-A-Ql/Gshark"
DEFAULT_SOURCE_EXE = ROOT / "build" / "bin" / "gshark-sentinel.exe"


@dataclass
class ReleaseConfig:
    version: str
    asset_name: str
    repo: str
    channel: str
    notes: str
    source_exe_path: Path
    output_dir: Path
    release_url: str
    asset_url: str
    skip_build: bool
    update_repo_manifest: bool


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def read_notes(version: str, inline_notes: str, notes_file: str) -> str:
    if inline_notes.strip():
        return inline_notes

    candidate_paths = []
    if notes_file.strip():
        candidate_paths.append(ROOT / notes_file)
    candidate_paths.append(ROOT / "release" / "notes" / f"{version}.md")

    for candidate in candidate_paths:
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")

    return ""


def compute_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_command(args: list[str], cwd: Path) -> None:
    subprocess.run(args, cwd=str(cwd), check=True)


def build_release(config: ReleaseConfig) -> tuple[Path, Path]:
    if not config.skip_build:
        print("[gshark] building desktop release with wails build")
        run_command(["wails", "build"], ROOT)

    if not config.source_exe_path.is_file():
        raise FileNotFoundError(f"source exe not found: {config.source_exe_path}")

    config.output_dir.mkdir(parents=True, exist_ok=True)

    release_exe_path = config.output_dir / config.asset_name
    shutil.copy2(config.source_exe_path, release_exe_path)
    print(f"[gshark] release asset prepared: {release_exe_path}")

    manifest_path = config.output_dir / "version.json"
    write_manifest(config, release_exe_path, manifest_path)

    if config.update_repo_manifest:
        repo_manifest_path = ROOT / "release" / "version.json"
        repo_manifest_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(manifest_path, repo_manifest_path)
        print(f"[gshark] repository manifest updated: {repo_manifest_path}")

    return release_exe_path, manifest_path


def write_manifest(config: ReleaseConfig, release_exe_path: Path, manifest_path: Path) -> None:
    sha256 = compute_sha256(release_exe_path)
    size = release_exe_path.stat().st_size
    manifest = {
        "version": config.version,
        "name": f"Gshark {config.version}",
        "published_at": utc_now_iso(),
        "release_url": config.release_url,
        "notes": config.notes,
        "channel": config.channel,
        "generated_at": utc_now_iso(),
        "assets": [
            {
                "name": config.asset_name,
                "download_url": config.asset_url,
                "size": size,
                "content_type": "application/vnd.microsoft.portable-executable",
                "sha256": sha256,
                "os": "windows",
                "arch": "amd64",
            }
        ],
    }

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"[gshark] update manifest written to {manifest_path}")
    print(f"[gshark] manifest asset: {config.asset_name}")
    print(f"[gshark] manifest sha256: {sha256}")


def build_config(args: argparse.Namespace) -> ReleaseConfig:
    version = args.version.strip()
    asset_name = args.asset_name.strip() or f"gshark.{version}.exe"
    output_dir = Path(args.output_dir).resolve() if args.output_dir else (ROOT / "release" / "out" / version)
    source_exe_path = Path(args.source_exe_path).resolve() if args.source_exe_path else DEFAULT_SOURCE_EXE
    release_url = args.release_url.strip() or f"https://github.com/{args.repo}/releases/tag/{version}"
    asset_url = args.asset_url.strip() or f"https://github.com/{args.repo}/releases/download/{version}/{asset_name}"
    notes = read_notes(version, args.notes, args.notes_file)

    return ReleaseConfig(
        version=version,
        asset_name=asset_name,
        repo=args.repo,
        channel=args.channel,
        notes=notes,
        source_exe_path=source_exe_path,
        output_dir=output_dir,
        release_url=release_url,
        asset_url=asset_url,
        skip_build=bool(args.skip_build),
        update_repo_manifest=not bool(args.no_repo_manifest_update),
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build desktop release package and generate release/version.json.",
    )
    parser.add_argument("version", help="release version, for example v0.0.5")
    parser.add_argument("--asset-name", default="", help="output asset filename")
    parser.add_argument("--repo", default=DEFAULT_REPO, help="GitHub repo slug")
    parser.add_argument("--channel", default="stable", help="release channel")
    parser.add_argument("--notes", default="", help="inline release notes")
    parser.add_argument("--notes-file", default="", help="custom release notes file path")
    parser.add_argument("--source-exe-path", default="", help="built desktop exe path")
    parser.add_argument("--output-dir", default="", help="release output directory")
    parser.add_argument("--release-url", default="", help="release page URL")
    parser.add_argument("--asset-url", default="", help="download URL for the release asset")
    parser.add_argument("--skip-build", action="store_true", help="skip wails build and reuse existing exe")
    parser.add_argument(
        "--no-repo-manifest-update",
        action="store_true",
        help="do not overwrite release/version.json in repository root",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    try:
        args = parse_args(argv)
        config = build_config(args)
        release_exe_path, manifest_path = build_release(config)
        print("[gshark] release package ready")
        print(f"[gshark] asset: {release_exe_path}")
        print(f"[gshark] manifest: {manifest_path}")
        if not config.notes.strip():
            print(f"[gshark] tip: create release/notes/{config.version}.md to manage release notes more easily")
        print(
            f"[gshark] next step: upload {config.asset_name} to GitHub Release {config.version}, then commit release/version.json"
        )
        return 0
    except subprocess.CalledProcessError as exc:
        print(f"[gshark] command failed with exit code {exc.returncode}: {exc.cmd}", file=sys.stderr)
        return exc.returncode or 1
    except Exception as exc:  # noqa: BLE001
        print(f"[gshark] release packaging failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
