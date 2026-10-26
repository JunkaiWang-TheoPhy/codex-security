"""Durable remediation state transitions for the Codex Security workbench."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sqlite3
import sys
from collections.abc import Callable
from contextlib import ExitStack, suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, BinaryIO

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from finalize_scan_contract import (
    ContractError,
    MissingScanLocalFileError,
    _read_scan_local_json_bytes,
    _read_sealed_scan,
    scan_local_file_version,
    scan_root_identity,
    stage_scan_local_bytes,
)
from workbench_constants import CLAIM_LEASE_SECONDS, DELIVERED_ACTION_LEASE_SECONDS
from workbench_target import git_command, git_output
from workbench_validation import optional_text, require_occurrence, require_uuid

COMMANDS = {
    "request-finding-remediation",
    "request-finding-remediation-action",
    "claim-finding-remediation-resend",
    "mark-finding-remediation-delivered",
    "release-finding-remediation-claim",
    "cancel-finding-remediation-request",
    "set-finding-remediation",
}
SCAN_STATUS_ERROR = "Remediation is available only for successfully completed scans."


def require_available(connection: sqlite3.Connection, args: Any, require_scan: Any) -> None:
    if args.command not in COMMANDS:
        return
    occurrence = require_occurrence(connection, args.occurrence_id)
    if require_scan(connection, occurrence["scan_id"])["status"] != "complete":
        raise SystemExit(SCAN_STATUS_ERROR)


def require_request(
    connection: sqlite3.Connection, request_id: str, occurrence: sqlite3.Row
) -> sqlite3.Row:
    current = connection.execute(
        "SELECT * FROM finding_remediation_attempts WHERE request_id = ?",
        (request_id,),
    ).fetchone()
    if current is None or current["occurrence_id"] != occurrence["id"]:
        raise SystemExit("Codex Security finding remediation request not found.")
    return current


def require_valid_patch(target: Path, patch: bytes) -> None:
    incomplete = (
        "The remediation patch omits file content. Generate a complete binary diff "
        "with Git's --binary option."
    )
    without_summaries = patch
    if re.search(rb"(?m)^(?:Binary files |Files |Only in )", patch):
        # These standalone lines are omitted changes in raw diffs. Git format-patch mail
        # may also contain them in its commit message or signature.
        if not re.match(
            rb"From (?:[0-9a-f]{40}|[0-9a-f]{64}) Mon Sep 17 00:00:00 2001\r?\n", patch
        ):
            raise SystemExit(incomplete)
        without_summaries = re.sub(rb"(?m)^(?:Binary files|Files) [^\n]* differ\r?$", b"", patch)
    # Numstat in a nested working directory can skip or misinterpret target-relative paths.
    root = (
        git_output(target, "rev-parse", "--show-toplevel") if without_summaries != patch else None
    )
    directory = ("-C", root) if root else ()

    def git(data: bytes, *arguments: str):
        result = git_command(
            target,
            *directory,
            *arguments,
            text=False,
            input_data=data,
            pathspec_environment={"LC_ALL": "C"},
        )
        if result.returncode == 127:
            raise SystemExit(
                "Validating a new remediation patch requires a trusted Git executable."
            )
        # Git may report a corrupt trailing binary block but return zero for an earlier file.
        if result.returncode or re.search(rb"(?m)^error: ", result.stderr):
            reason = result.stderr.decode(errors="replace").strip()
            raise SystemExit(f"Could not parse the remediation patch: {reason}")
        return result.stdout

    # Parse every header and hunk, then skip checkout reads and repository clean filters.
    apply = ("apply", "--no-index", "--whitespace=nowarn")
    git(patch, *apply, "--check", "--exclude=*", "-")
    stats = (*apply, "--numstat", "-")
    if without_summaries != patch and git(patch + b"\n", *stats) != git(
        without_summaries + b"\n", *stats
    ):
        raise SystemExit(incomplete)

    binary_oid_width = None
    for header in re.finditer(
        rb"(?m)^diff --git [^\n]+\n((?:(?!diff )[a-z][^\n]*\n)*?)"
        rb"index ([^\s.]+)\.\.([^\s.]+)(?: [0-7]+)?\r?(?:\n|\Z)",
        patch,
    ):
        metadata, old, new = header.groups()
        binary = patch.startswith((b"GIT binary patch\n", b"GIT binary patch\r\n"), header.end())
        if not binary and (
            not metadata.startswith(b"deleted file mode ")
            or new.strip(b"0")
            or patch.startswith((b"--- ", b"@@ "), header.end())
        ):
            continue
        if not binary:
            # --irreversible-delete omits the preimage. Only an empty file needs no hunk,
            # and its deletion works across Git object formats.
            empty_blobs = (
                hashlib.sha1(b"blob 0\0", usedforsecurity=False).hexdigest().encode(),
                hashlib.sha256(b"blob 0\0").hexdigest().encode(),
            )
            if not any(digest.startswith(old.lower()) for digest in empty_blobs):
                raise SystemExit(incomplete)
            continue
        if binary_oid_width is None:
            binary_oid_width = len(git(b"", "hash-object", "--no-filters", "--stdin").strip())
        if (
            len(old) != binary_oid_width
            or len(new) != binary_oid_width
            or not re.fullmatch(rb"[0-9a-fA-F]+", old + new)
        ):
            raise SystemExit(
                "A binary patch requires full object IDs in the selected target's Git object format."
            )
        # Reversing an addition only deletes it. Other binary changes need the preimage.
        if not old.strip(b"0"):
            continue
        separator = re.compile(rb"\r?\n\r?\n").search(patch, header.end())
        if not separator or not patch.startswith((b"literal ", b"delta "), separator.end()):
            raise SystemExit(incomplete)


def patch_metadata(
    current: sqlite3.Row,
    args: argparse.Namespace,
    patch: bytes | None,
    resolve_path: Callable[[str], str],
) -> tuple[str | None, str | None]:
    path = args.patch_path
    digest = args.patch_digest
    if patch is not None:
        if args.state != "generated" or path is not None or digest is not None:
            raise SystemExit("Supply patch only for generation, without a patch path or digest.")
        path = current["patch_path"] or (
            f"artifacts/remediation/{current['occurrence_id']}/{current['request_id']}/"
            f"{current['pending_action_claim_token']}.patch"
        )
        digest = f"sha256:{hashlib.sha256(patch).hexdigest()}"
    else:
        if path is not None:
            path = resolve_path(path)
        if digest is not None:
            digest = optional_text(digest, maximum=71)
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest or ""):
                raise SystemExit("patch-digest must use sha256:<64 lowercase hex characters>.")
    if path is not None and current["patch_path"] not in (None, path):
        raise SystemExit("A remediation attempt cannot replace its reviewed patch path.")
    if digest is not None and current["patch_digest"] not in (None, digest):
        raise SystemExit("A remediation attempt cannot replace its reviewed patch digest.")
    return path or current["patch_path"], digest or current["patch_digest"]


def same_file_version(
    original: tuple[os.stat_result, int], current: tuple[os.stat_result, int]
) -> bool:
    before, before_change = original
    after, after_change = current
    return (
        os.path.samestat(before, after)
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
        and before_change == after_change
    )


def file_digest_and_version(source: BinaryIO, label: str) -> tuple[str, tuple[os.stat_result, int]]:
    before = scan_local_file_version(source.fileno())
    digest = hashlib.sha256()
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
    after = scan_local_file_version(source.fileno())
    if not same_file_version(before, after):
        raise SystemExit(f"The {label} changed while it was being verified.")
    return f"sha256:{digest.hexdigest()}", after


def matching_patch_metadata(source: BinaryIO, expected_digest: str) -> tuple[os.stat_result, int]:
    digest, version = file_digest_and_version(source, "scan-local patch")
    if digest != expected_digest:
        raise SystemExit("Patch digest does not match the scan-local patch file.")
    return version


def patch_manifest_version(
    db: Any, scan: sqlite3.Row, scan_dir: Path
) -> tuple[str, tuple[os.stat_result, int]]:
    manifest_path = db.ARTIFACTS["manifest"]
    expected = scan["seal_manifest_digest"]
    if expected is None:
        # Historical manifests can have different JSON formatting. Bind their original bytes.
        saved, raw = _read_scan_local_json_bytes(scan_dir, manifest_path, manifest_path)
        manifest, _, _, _ = _read_sealed_scan(scan_dir, None, "remediation")
        if saved != manifest:
            raise SystemExit("The sealed scan manifest changed during validation.")
        db.verify_manifest_binding(scan, manifest)
        expected = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    with db.open_scan_local_file(scan_dir, manifest_path) as source:
        digest, version = file_digest_and_version(source, "sealed scan manifest")
    if digest != expected:
        raise SystemExit("The sealed scan manifest changed after completion.")
    return digest, version


def save_patch(
    db: Any,
    connection: sqlite3.Connection,
    scan_id: str,
    current: sqlite3.Row,
    path: str,
    digest: str,
    patch: bytes,
    record_update: Callable[[], None],
) -> None:
    def cleanup_root() -> Path | None:
        # A failed cleanup lookup must preserve the original admission error.
        with suppress(sqlite3.Error, SystemExit):
            return Path(db.require_scan(connection, scan_id)["scan_dir"])
        return None

    def admit() -> Path:
        record_update()
        latest = db.require_scan(connection, scan_id)
        directory = db.require_canonical_scan_directory(Path(latest["scan_dir"]))
        if scan_root_identity(directory)[1] != identity:
            raise SystemExit("The scan directory changed after seal validation.")
        with db.open_scan_local_file(directory, db.ARTIFACTS["manifest"]) as named:
            current_version = scan_local_file_version(named.fileno())
        if latest["seal_manifest_digest"] not in (None, manifest_digest) or not same_file_version(
            manifest_version, current_version
        ):
            raise SystemExit("The sealed scan manifest changed after completion.")
        return directory

    def verify_name(directory: Path, expected: tuple[os.stat_result, int]) -> None:
        with db.open_scan_local_file(directory, path) as named:
            if not same_file_version(expected, scan_local_file_version(named.fileno())):
                raise SystemExit("The scan-local patch changed during generation.")
        if scan_root_identity(directory)[1] != identity:
            raise SystemExit("The scan directory changed while saving the patch.")

    published = None
    retried_directory = None
    with ExitStack() as staging:
        while True:
            scan = db.require_scan(connection, scan_id)
            try:
                scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
                scan_dir, identity = scan_root_identity(scan_dir)
                manifest_digest, manifest_version = patch_manifest_version(db, scan, scan_dir)
                publish = None
                if current["patch_path"] is None:
                    with suppress(FileExistsError):
                        publish = staging.enter_context(
                            stage_scan_local_bytes(
                                scan_dir,
                                path,
                                patch,
                                expected_root_identity=identity,
                                owner_read_write=True,
                                cleanup_root=cleanup_root,
                            )
                        )
                break
            except (ContractError, OSError, SystemExit) as exc:
                # Archiving moves the directory before committing its new location.
                with connection:
                    connection.execute("BEGIN IMMEDIATE")
                    directory = db.require_scan(connection, scan_id)["scan_dir"]
                if directory == scan["scan_dir"]:
                    # A rolled-back archive restores a temporarily missing path.
                    cause: BaseException | None = exc
                    while cause and not isinstance(
                        cause, (FileNotFoundError, MissingScanLocalFileError)
                    ):
                        cause = cause.__cause__
                    if cause is None or directory == retried_directory:
                        raise
                    retried_directory = directory
        if publish is not None:
            directory = admit()
            try:
                published = publish(directory)
            except FileExistsError:
                # Read a competing winner outside SQLite, then claim the same version again.
                connection.rollback()
    if published is not None:
        verify_name(directory, published)
        return
    scan = db.require_scan(connection, scan_id)
    metadata = db.require_matching_patch_digest(scan, path, digest)
    verify_name(admit(), metadata)


def remediation_claim_is_active(remediation: sqlite3.Row) -> bool:
    if remediation["pending_action_claim_token"] is None:
        return False
    delivered_at = remediation["pending_action_delivered_at"]
    claimed_at = delivered_at or remediation["pending_action_claimed_at"]
    if not isinstance(claimed_at, str):
        return True
    try:
        if claimed_at.endswith(("Z", "z")):
            claimed_at = claimed_at[:-1] + "+00:00"
        parsed = datetime.fromisoformat(claimed_at)
        if parsed.tzinfo is None:
            return True
    except ValueError:
        return True
    lease_seconds = DELIVERED_ACTION_LEASE_SECONDS if delivered_at else CLAIM_LEASE_SECONDS
    return parsed > datetime.now(timezone.utc) - timedelta(seconds=lease_seconds)


def require_transition(current: str, requested: str) -> None:
    allowed = {
        "requested": {"requested", "generated", "failed"},
        "generated": {"generated", "applied", "failed"},
        "applied": {"applied", "verifying", "failed"},
        "verifying": {"verifying", "verified", "failed"},
        "verified": {"verifying", "verified"},
        "failed": {"generated", "applied", "verifying", "verified", "failed"},
    }
    if requested not in allowed.get(current, set()):
        raise SystemExit(f"Finding remediation cannot move from {current} to {requested}.")


def require_pending_action(current: sqlite3.Row, requested: str) -> None:
    pending_action = current["pending_action"]
    if pending_action is not None:
        allowed = {
            "generate": {"generated", "failed"},
            "apply": {"applied", "failed"},
            "verify": {"verifying", "verified", "failed"},
        }
        if requested not in allowed[pending_action]:
            raise SystemExit(
                f"Pending remediation action {pending_action} cannot record state {requested}."
            )
        return
    required_action = {
        ("requested", "generated"): "generate",
        ("generated", "applied"): "apply",
        ("applied", "verifying"): "verify",
    }.get((current["state"], requested))
    if required_action is not None:
        raise SystemExit(
            f"Request {required_action} before recording remediation state {requested}."
        )


def cancel_finding_remediation_request(
    connection: sqlite3.Connection, args: argparse.Namespace
) -> str:
    request_id = require_uuid(args.request_id, "request-id")
    action_token = require_uuid(args.action_token, "action-token")
    connection.execute("BEGIN IMMEDIATE")
    with connection:
        occurrence = require_occurrence(connection, args.occurrence_id)
        current = connection.execute(
            "SELECT * FROM finding_remediation_attempts WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if current is None:
            return str(occurrence["scan_id"])
        if current["occurrence_id"] != occurrence["id"]:
            raise SystemExit("This remediation request belongs to a different finding.")
        if current["pending_action"] is None:
            return str(occurrence["scan_id"])
        if current["state"] == "failed" and current["pending_action_claim_token"] is None:
            return str(occurrence["scan_id"])
        if current["pending_action_claim_token"] != action_token:
            raise SystemExit("This remediation host request is owned by a different action token.")
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        if current["state"] == "failed":
            connection.execute(
                """
                UPDATE finding_remediation_attempts
                SET pending_action_claimed_at = NULL, pending_action_claim_token = NULL,
                    pending_action_delivered_at = NULL, updated_at = ?
                WHERE request_id = ? AND pending_action_claim_token = ?
                """,
                (timestamp, request_id, action_token),
            )
        elif current["pending_action"] == "generate":
            _cancel_generation(
                connection, occurrence["id"], request_id, timestamp, current["state"]
            )
            connection.execute(
                "UPDATE scans SET updated_at = ? WHERE id = ?",
                (timestamp, occurrence["scan_id"]),
            )
        else:
            connection.execute(
                """
                UPDATE finding_remediation_attempts
                SET state = CASE
                        WHEN pending_action = 'verify' AND state = 'verifying' THEN 'applied'
                        ELSE state
                    END,
                    pending_action = NULL, pending_action_claimed_at = NULL,
                    pending_action_claim_token = NULL, pending_action_delivered_at = NULL,
                    version = version + 1, updated_at = ?
                WHERE request_id = ? AND pending_action_claim_token = ?
                """,
                (timestamp, request_id, action_token),
            )
    return str(occurrence["scan_id"])


def _cancel_generation(
    connection: sqlite3.Connection,
    occurrence_id: str,
    request_id: str,
    timestamp: str,
    state: str,
) -> None:
    if state != "requested":
        raise SystemExit("Only a requested patch generation can be canceled.")
    connection.execute(
        "DELETE FROM finding_remediation_attempts WHERE request_id = ?", (request_id,)
    )
    previous = connection.execute(
        """
        SELECT * FROM finding_remediation_attempts
        WHERE occurrence_id = ?
        ORDER BY created_at DESC, rowid DESC
        LIMIT 1
        """,
        (occurrence_id,),
    ).fetchone()
    if previous is None or previous["state"] != "superseded":
        return
    restored_state = "applied" if previous["applied_content_digest"] is not None else "generated"
    connection.execute(
        """
        UPDATE finding_remediation_attempts
        SET state = ?, version = version + 1, updated_at = ?
        WHERE request_id = ? AND state = 'superseded'
        """,
        (restored_state, timestamp, previous["request_id"]),
    )


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
