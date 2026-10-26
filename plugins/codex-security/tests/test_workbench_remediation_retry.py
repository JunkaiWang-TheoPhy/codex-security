from __future__ import annotations

import argparse
import io
import os
import secrets
import sqlite3
import subprocess
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest
from workbench_test_support import (
    cancel_remediation_request,
    claim_remediation_resend,
    initialize_git_repository,
    mark_remediation_delivered,
    request_remediation,
    request_remediation_action,
    scan_command,
    set_remediation,
    set_triage,
    start_saved_scan,
    write_completed_contract,
    write_remediation_patch,
)


def update_remediation(
    state_dir: Path,
    occurrence_id: str,
    request_id: str,
    action_token: str,
    expected_version: int,
    state: str,
    *extra: str,
) -> dict[str, Any]:
    result = set_remediation(
        state_dir, occurrence_id, request_id, action_token, str(expected_version), state, *extra
    )
    return result["scan"]["findings"][0]["remediationState"]


@pytest.mark.cross_platform
def test_generated_patch_requires_binary_contents(
    tmp_path: Path, workbench_api, monkeypatch
) -> None:
    repository = tmp_path / "repo"
    initialize_git_repository(repository)
    target = repository / "nested" / "scan" / "target"
    target.mkdir(parents=True)
    asset = target / "asset.bin"
    asset.write_bytes(b"\0before")
    subprocess.run(["git", "add", "asset.bin"], cwd=target, check=True)
    diff = ["git", "diff", "--relative"]
    added = subprocess.check_output([*diff, "--cached", "--binary"], cwd=target)
    subprocess.run(["git", "commit", "-qm", "Add asset"], cwd=target, check=True)
    asset.write_bytes(b"\0after")
    summary = subprocess.check_output(diff, cwd=target)
    binary = subprocess.check_output([*diff, "--binary"], cwd=target)
    notice = summary.splitlines(keepends=True)[-1]
    prose = (
        notice.decode()
        + "Only in target: new-file\nindex 1234567..89abcde 100644\nGIT binary patch"
    )
    subprocess.run(["git", "commit", "-qam", "Update asset", "-m", prose], cwd=target, check=True)
    email = ["git", "format-patch", "-1", "--stdout", "--relative", "--signature", prose]
    mail = subprocess.check_output(email, cwd=target)
    mail_summary = subprocess.check_output([*email, "--no-binary"], cwd=target)
    asset.write_bytes(b"\0before")

    validate = workbench_api["remediation_state"].require_valid_patch
    hunk = b"--- a/note\n+++ b/note\n@@ -1 +1 @@\n-old\n+Binary files a/a and b/a differ\n"
    forward_only = binary.partition(b"\n\n")[0] + b"\n\n"
    with pytest.raises(SystemExit, match="Could not parse the remediation patch"):
        validate(target, summary.removesuffix(notice))
    for incomplete in (
        summary,
        summary.rstrip(b"\n"),
        hunk + summary,
        mail_summary,
        notice + hunk,
        hunk + notice,
        hunk + b"Only in tree: new-file\n",
        hunk + forward_only,
        binary + forward_only,
    ):
        with pytest.raises(SystemExit, match="--binary option"):
            validate(target, incomplete)

    data_line = binary.split(b"GIT binary patch\n", 1)[1].splitlines()[1]
    corrupt = binary.replace(data_line, b"!", 1)
    monkeypatch.setenv("GIT_TRACE", "1")
    with pytest.raises(SystemExit, match="error: corrupt binary patch"):
        validate(target, hunk + corrupt)
    validate(target, hunk + binary)
    validate(target, mail)
    validate(target, added.partition(b"\n\n")[0] + b"\n\n")
    assert asset.read_bytes() == b"\0before"


@pytest.mark.cross_platform
@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
def test_generated_patch_preserves_deletions_and_uses_target_binary_ids(
    tmp_path: Path, workbench_api, object_format: str
) -> None:
    repo = tmp_path / object_format
    other_format = "sha256" if object_format == "sha1" else "sha1"
    other = tmp_path / other_format
    for directory in (repo, other):
        subprocess.run(
            ["git", "init", "-q", f"--object-format={directory.name}", directory], check=True
        )

    def git(*args: str) -> bytes:
        return subprocess.check_output(["git", *args], cwd=repo)

    (repo / "text").write_bytes(b"old\n")
    (repo / "empty").touch()
    (repo / "asset").write_bytes(b"\0old")
    git("add", ".")
    (repo / "text").unlink()
    (repo / "empty").unlink()
    (repo / "asset").write_bytes(b"\0new")
    validate = workbench_api["remediation_state"].require_valid_patch
    with pytest.raises(SystemExit, match="omits file content"):
        validate(repo, git("diff", "--irreversible-delete", "--", "text"))
    text = git("diff", "--full-index", "--", "text")
    empty = git("diff", "--abbrev=4", "--", "empty")
    for target in (repo, other, tmp_path):
        validate(target, text)
        validate(target, empty)

    binary = git("diff", "--binary", "--", "asset")
    validate(repo, binary)
    index = next(line for line in binary.splitlines() if line.startswith(b"index "))
    with pytest.raises(SystemExit, match="full object IDs"):
        validate(repo, binary.replace(index, b"index 1234567..89abcde 100644"))
    with pytest.raises(SystemExit, match="Git object format"):
        validate(other, binary)
    if object_format == "sha1":
        validate(tmp_path, binary)
    else:
        with pytest.raises(SystemExit, match="Git object format"):
            validate(tmp_path, binary)


@pytest.fixture
def pending_generation(tmp_path, monkeypatch):
    state, target = tmp_path / "state", tmp_path / "target"
    target.mkdir()
    (target / "source.txt").write_text("before\n")
    scan_id, scan_dir = start_saved_scan(state, target, tmp_path / "scans")
    write_completed_contract(scan_dir, scan_id, target, relative_path="source.txt")
    completed = scan_command(state, "complete-scan", scan_id)["scan"]
    occurrence = completed["findings"][0]["occurrenceId"]
    request, token = str(uuid.uuid4()), str(uuid.uuid4())
    request_remediation(state, occurrence, request, token)
    database = state / "workbench.sqlite3"
    patch = b"--- a/source.txt\n+++ b/source.txt\n@@ -1 +1 @@\n-before\n+after\n"
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(patch)))
    args = argparse.Namespace(
        occurrence_id=occurrence,
        request_id=request,
        action_token=token,
        expected_version=1,
        state="generated",
        patch_stdin=True,
        patch_path=None,
        patch_digest=None,
        base_revision=None,
        summary=None,
        verification_summary=None,
    )
    return database, scan_dir, scan_id, args, patch


@pytest.mark.cross_platform
@pytest.mark.parametrize("change_manifest", [False, True])
def test_generate_legacy_patch_validates_seal_before_taking_writer_lock(
    pending_generation, workbench_api, monkeypatch, change_manifest: bool
) -> None:
    database, scan_dir, scan_id, args, patch = pending_generation
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE scans SET seal_manifest_digest = NULL WHERE id = ?", (scan_id,))

    manifest = scan_dir / "scan-manifest.json"
    manifest.write_bytes(manifest.read_bytes() + b"\n")
    remediation = workbench_api["remediation_state"]
    read_seal = remediation._read_sealed_scan
    validated = []

    def read_without_writer_lock(*args):
        with sqlite3.connect(database, timeout=0) as writer:
            writer.execute("BEGIN IMMEDIATE")
            result = read_seal(*args)
        validated.append(args[0])
        if change_manifest:
            manifest.write_bytes(manifest.read_bytes() + b"\n")
        return result

    monkeypatch.setattr(remediation, "_read_sealed_scan", read_without_writer_lock)
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        if change_manifest:
            with pytest.raises(SystemExit, match="sealed scan manifest changed"):
                workbench_api["set_finding_remediation"](connection, args)
            row = connection.execute(
                "SELECT state, version, patch_path FROM finding_remediation_attempts WHERE request_id = ?",
                (args.request_id,),
            ).fetchone()
            assert tuple(row) == ("requested", 1, None)
            assert not list(scan_dir.rglob("*.patch"))
        else:
            result = workbench_api["set_finding_remediation"](connection, args)
            relative = result["scan"]["findings"][0]["remediationState"]["patchPath"]
            assert (scan_dir / relative).read_bytes() == patch
    assert validated == [scan_dir]


@pytest.mark.cross_platform
@pytest.mark.parametrize("scenario", ["new", "existing", "canceled"])
def test_generate_keeps_the_database_writer_available_during_patch_io(
    pending_generation, workbench_api, monkeypatch, scenario
):
    database, scan_dir, _, args, patch = pending_generation
    destination = (
        scan_dir
        / f"artifacts/remediation/{args.occurrence_id}/{args.request_id}/{args.action_token}.patch"
    )
    remediation = workbench_api["remediation_state"]
    acquired = []
    if scenario == "existing":
        destination.parent.mkdir(parents=True)
        destination.write_bytes(patch)
        verify = remediation.matching_patch_metadata

        def verify_with_writer(*args):
            with sqlite3.connect(database, timeout=0) as other:
                other.execute("BEGIN IMMEDIATE")
                acquired.append("existing")
                return verify(*args)

        monkeypatch.setattr(remediation, "matching_patch_metadata", verify_with_writer)
    else:
        stage = remediation.stage_scan_local_bytes

        @contextmanager
        def stage_with_writer(*stage_args, **options):
            with sqlite3.connect(database, timeout=0) as other:
                other.row_factory = sqlite3.Row
                other.execute("BEGIN IMMEDIATE")
                with stage(*stage_args, **options) as publish:
                    acquired.append(scenario)
                    other.commit()
                    if scenario == "canceled":
                        remediation.cancel_finding_remediation_request(other, args)
                    yield publish

        monkeypatch.setattr(remediation, "stage_scan_local_bytes", stage_with_writer)
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        if scenario == "canceled":
            with pytest.raises(SystemExit, match="remediation request changed"):
                workbench_api["set_finding_remediation"](connection, args)
            assert not destination.exists()
            assert not list(destination.parent.glob("*.tmp"))
            assert (
                connection.execute(
                    "SELECT 1 FROM finding_remediation_attempts WHERE request_id = ?",
                    (args.request_id,),
                ).fetchone()
                is None
            )
        else:
            result = workbench_api["set_finding_remediation"](connection, args)
            assert result["scan"]["findings"][0]["remediationState"]["state"] == "generated"
            assert destination.read_bytes() == patch
    assert acquired == [scenario]


@pytest.mark.cross_platform
@pytest.mark.parametrize("matching", [False, True], ids=["different-patch", "identical-patch"])
def test_generate_preserves_patch_published_by_another_writer(
    pending_generation, workbench_api, monkeypatch, matching
):
    database, scan_dir, _, args, patch = pending_generation
    destination = (
        scan_dir
        / f"artifacts/remediation/{args.occurrence_id}/{args.request_id}/{args.action_token}.patch"
    )
    winner = patch if matching else patch.replace(b"+after", b"+another")
    token_hex = secrets.token_hex
    created = []

    def publish_before_temp_file(size):
        # Both backends allocate the temp name after checking the destination.
        with destination.open("xb") as output:
            output.write(winner)
        created.append(destination.stat())
        return token_hex(size)

    monkeypatch.setattr(secrets, "token_hex", publish_before_temp_file)
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        if matching:
            result = workbench_api["set_finding_remediation"](connection, args)
            assert result["scan"]["findings"][0]["remediationState"]["state"] == "generated"
        else:
            with pytest.raises(SystemExit, match="Patch digest does not match"):
                workbench_api["set_finding_remediation"](connection, args)
            row = connection.execute(
                "SELECT state, version, patch_path FROM finding_remediation_attempts WHERE request_id = ?",
                (args.request_id,),
            ).fetchone()
            assert tuple(row) == ("requested", 1, None)
    assert len(created) == 1 and os.path.samestat(created[0], destination.stat())
    assert destination.read_bytes() == winner
    assert list(destination.parent.iterdir()) == [destination]


@pytest.mark.cross_platform
def test_generate_requires_the_published_patch_at_its_recorded_path(
    pending_generation, workbench_api, monkeypatch
):
    database, scan_dir, _, args, patch = pending_generation
    remediation = workbench_api["remediation_state"]
    stage = remediation.stage_scan_local_bytes
    request_dir = scan_dir / "artifacts" / "remediation" / args.occurrence_id / args.request_id
    moved = request_dir.with_name("moved-request")

    @contextmanager
    def move_published_patch(*args, **kwargs):
        with stage(*args, **kwargs) as publish:
            yield publish
        request_dir.rename(moved)

    monkeypatch.setattr(remediation, "stage_scan_local_bytes", move_published_patch)
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        with pytest.raises(SystemExit, match="scan-local regular file"):
            workbench_api["set_finding_remediation"](connection, args)
        row = connection.execute(
            "SELECT state, version, patch_path FROM finding_remediation_attempts WHERE request_id = ?",
            (args.request_id,),
        ).fetchone()
        assert tuple(row) == ("requested", 1, None)
    assert not request_dir.exists()
    assert (moved / f"{args.action_token}.patch").read_bytes() == patch


def test_failed_remediation_steps_can_retry_or_regenerate(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    source = target / "source.txt"
    source.write_text("vulnerable\n")
    scan_id, scan_dir = start_saved_scan(state_dir, target, tmp_path / "scans")
    write_completed_contract(scan_dir, scan_id, target, relative_path=source.name)
    completed = scan_command(state_dir, "complete-scan", scan_id)["scan"]
    occurrence_id = str(completed["findings"][0]["occurrenceId"])

    request_id = str(uuid.uuid4())
    action_token = str(uuid.uuid4())
    request_remediation(state_dir, occurrence_id, request_id, action_token)
    mark_remediation_delivered(state_dir, occurrence_id, request_id, action_token)
    destination = (
        scan_dir / f"artifacts/remediation/{occurrence_id}/{request_id}/{action_token}.patch"
    )
    generation = (state_dir, occurrence_id, request_id, action_token, "1", "generated")
    proposed_patch = "--- a/source.txt\n+++ b/source.txt\n@@ -1 +1 @@\n-vulnerable\n+updated\n"
    for invalid_patch in ("", " \t\n", "Updated the source.\n", proposed_patch.removesuffix("\n")):
        rejected = set_remediation(
            *generation, "--patch-stdin", input_text=invalid_patch, check=False
        )
        assert rejected["returncode"] != 0
        assert "Could not parse the remediation patch" in rejected["stderr"]
        assert not destination.exists()

    destination.parent.mkdir(parents=True, exist_ok=True)
    write_remediation_patch(destination)
    existing_patch = destination.read_bytes()
    rejected = set_remediation(*generation, "--patch-stdin", input_text=proposed_patch, check=False)
    assert rejected["returncode"] != 0
    save_error = rejected["stderr"].strip()
    assert "Could not save the remediation patch" in save_error
    assert destination.read_bytes() == existing_patch
    failed = update_remediation(
        state_dir,
        occurrence_id,
        request_id,
        action_token,
        1,
        "failed",
        "--summary",
        save_error,
    )
    assert failed["summary"] == save_error
    assert failed["pendingAction"] == "generate"
    assert failed["actionClaimToken"] is None
    assert failed["actionDeliveredAt"] is None

    closed = set_triage(
        state_dir,
        occurrence_id,
        "closed",
        "--close-reason",
        "wont_fix",
        "--note",
        "Closing is allowed after the remediation worker has failed.",
    )["scan"]
    assert closed["findings"][0]["triage"]["status"] == "closed"
    set_triage(state_dir, occurrence_id, "open")

    resend_token = str(uuid.uuid4())
    resent = claim_remediation_resend(state_dir, occurrence_id, request_id, resend_token)["scan"]
    assert resent["findings"][0]["remediationState"]["actionClaimToken"] == resend_token
    delivered = mark_remediation_delivered(state_dir, occurrence_id, request_id, resend_token)[
        "scan"
    ]
    assert delivered["findings"][0]["remediationState"]["actionDeliveredAt"]
    canceled = cancel_remediation_request(state_dir, occurrence_id, request_id, resend_token)[
        "scan"
    ]["findings"][0]["remediationState"]
    assert canceled["state"] == "failed"
    assert canceled["pendingAction"] == "generate"
    assert canceled["actionClaimToken"] is None
    replayed = cancel_remediation_request(state_dir, occurrence_id, request_id, resend_token)[
        "scan"
    ]["findings"][0]["remediationState"]
    assert replayed == canceled

    resend_token = str(uuid.uuid4())
    claim_remediation_resend(state_dir, occurrence_id, request_id, resend_token)

    failed_request_id = request_id
    request_id = str(uuid.uuid4())
    action_token = str(uuid.uuid4())
    blocked = request_remediation(state_dir, occurrence_id, request_id, action_token, check=False)
    assert blocked["returncode"] != 0
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            """
            UPDATE finding_remediation_attempts
            SET pending_action_claimed_at = ?
            WHERE request_id = ?
            """,
            ("2000-01-01T00:00:00Z", failed_request_id),
        )
    regenerated = request_remediation(state_dir, occurrence_id, request_id, action_token)["scan"][
        "findings"
    ][0]["remediationState"]
    assert regenerated["state"] == "requested"

    no_newline_patch = proposed_patch + r"\ No newline at end of file"
    generated = set_remediation(
        state_dir,
        occurrence_id,
        request_id,
        action_token,
        "1",
        "generated",
        "--patch-stdin",
        input_text=no_newline_patch,
    )["scan"]["findings"][0]["remediationState"]
    patch_path = scan_dir / generated["patchPath"]
    assert patch_path.read_text(encoding="utf-8") == no_newline_patch

    apply_token = str(uuid.uuid4())
    request_remediation_action(state_dir, occurrence_id, request_id, "2", "apply", apply_token)
    subprocess.run(["git", "apply", "--no-index", str(patch_path)], cwd=target, check=True)
    failed = update_remediation(
        state_dir,
        occurrence_id,
        request_id,
        apply_token,
        3,
        "failed",
        "--summary",
        "Patch application was interrupted after changing the checkout.",
    )
    assert failed["pendingAction"] == "apply"
    apply_retry_token = str(uuid.uuid4())
    claim_remediation_resend(state_dir, occurrence_id, request_id, apply_retry_token)
    applied = update_remediation(
        state_dir,
        occurrence_id,
        request_id,
        apply_retry_token,
        4,
        "applied",
        "--base-revision",
        "unversioned",
    )
    assert applied["state"] == "applied"
    assert applied["summary"] is None

    verify_token = str(uuid.uuid4())
    request_remediation_action(state_dir, occurrence_id, request_id, "5", "verify", verify_token)
    mark_remediation_delivered(state_dir, occurrence_id, request_id, verify_token)
    update_remediation(
        state_dir,
        occurrence_id,
        request_id,
        verify_token,
        6,
        "verifying",
        "--base-revision",
        "unversioned",
    )
    failed = update_remediation(
        state_dir,
        occurrence_id,
        request_id,
        verify_token,
        7,
        "failed",
        "--summary",
        "Verification could not reach the dependency registry from the sandbox.",
    )
    assert failed["pendingAction"] == "verify"
    assert failed["actionClaimToken"] is None
    assert failed["actionDeliveredAt"] is None
    canceled = cancel_remediation_request(state_dir, occurrence_id, request_id, verify_token)[
        "scan"
    ]["findings"][0]["remediationState"]
    assert canceled == failed
    verify_retry_token = str(uuid.uuid4())
    claim_remediation_resend(state_dir, occurrence_id, request_id, verify_retry_token)
    delivered = mark_remediation_delivered(
        state_dir, occurrence_id, request_id, verify_retry_token
    )["scan"]["findings"][0]["remediationState"]
    assert delivered["actionDeliveredAt"]
    canceled = cancel_remediation_request(state_dir, occurrence_id, request_id, verify_retry_token)[
        "scan"
    ]["findings"][0]["remediationState"]
    assert canceled["state"] == "failed"
    assert canceled["pendingAction"] == "verify"
    assert canceled["summary"] == failed["summary"]
    assert canceled["version"] == failed["version"]
    assert canceled["actionClaimToken"] is None
    assert canceled["actionClaimedAt"] is None
    assert canceled["actionDeliveredAt"] is None
    verify_retry_token = str(uuid.uuid4())
    claim_remediation_resend(state_dir, occurrence_id, request_id, verify_retry_token)
    verified = update_remediation(
        state_dir,
        occurrence_id,
        request_id,
        verify_retry_token,
        8,
        "verified",
        "--base-revision",
        "unversioned",
        "--verification-summary",
        "Focused regression tests passed after permission was granted.",
    )
    assert verified["state"] == "verified"
    assert verified["summary"] is None
