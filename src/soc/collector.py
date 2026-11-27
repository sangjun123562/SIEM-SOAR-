from __future__ import annotations

import os
import hashlib
from dataclasses import dataclass
from pathlib import Path

from .models import CollectionError, NormalizedEvent, RawLogRecord
from .normalizer import ALLOWED_INGEST_MODES, NormalizationError, normalize_log_line
from .storage import SocStorage


@dataclass(frozen=True)
class CollectResult:
    """Summary returned by a single file collection pass."""

    processed_lines: int
    inserted_records: int
    previous_offset: int
    new_offset: int
    skipped_lines: int = 0


@dataclass
class StartupBoundary:
    """수집기를 켤 때 로그 파일이 어디까지 쓰여 있었는지 파일별로 기억한다."""

    # 시작할 때 본 파일의 고유 번호와 크기다. 파일이 없었으면 빈 값과 0으로 둔다.
    file_inode: str = ""
    size: int = 0
    # 시작할 때 파일 상태를 확인했는지 적는다. 확인하지 못했으면 처음 읽은 줄까지 조사용으로 둔다.
    checked: bool = True


def _generation_file_key(file_key: str, generation: int) -> str:
    return file_key if generation <= 0 else f"{file_key}#g{generation}"


def _parse_complete_bytes(
    *,
    source: str,
    record_file_key: str,
    complete_bytes: bytes,
    start_offset: int,
    collection_mode: str,
    isolate_errors: bool = False,
    replay_before_offset: int | None = None,
) -> tuple[list[tuple[RawLogRecord, NormalizedEvent]], list[CollectionError]]:
    """Parse complete lines; isolate corrupt syntax/encoding lines or all errors when isolate_errors=True."""
    records: list[tuple[RawLogRecord, NormalizedEvent]] = []
    errors: list[CollectionError] = []
    cursor = start_offset
    for raw_bytes in complete_bytes.splitlines(keepends=True):
        line_offset = cursor
        cursor += len(raw_bytes)
        # 재시작 전에 쓰기 시작한 줄은 나중에 완성돼도 과거 기록이다.
        line_mode = (
            "replay"
            if (replay_before_offset is not None and line_offset < replay_before_offset)
            else collection_mode
        )
        try:
            decoded = raw_bytes.decode("utf-8")
            if not decoded.strip():
                continue
            raw_rec, norm_evt = normalize_log_line(
                decoded,
                source=source,
                file_path=record_file_key,
                line_offset=line_offset,
                collection_mode=line_mode,
            )
            records.append((raw_rec, norm_evt))
        except Exception as exc:
            is_corrupt_syntax = isinstance(exc, UnicodeDecodeError) or (
                isinstance(exc, NormalizationError) and "invalid JSON log line" in str(exc)
            )
            if not isolate_errors and not is_corrupt_syntax:
                raise
            code = ("invalid_utf8" if isinstance(exc, UnicodeDecodeError) else
                    "invalid_json" if is_corrupt_syntax else
                    "normalization_error" if isinstance(exc, NormalizationError) else "unexpected_error")
            errors.append(CollectionError(source, record_file_key, line_offset, len(raw_bytes),
                hashlib.sha256(raw_bytes).hexdigest(), code, line_mode))
            print(
                f"[collector] quarantined invalid line source={source} file={record_file_key} offset={line_offset}: {type(exc).__name__}",
                flush=True,
            )
    return records, errors


def _skip_reset_partial(storage, source: str, inode: str, offset: int, chunk: bytes) -> tuple[int, bytes]:
    if not hasattr(storage, "get_file_state"):
        return offset, chunk
    boundary, boundary_inode, partial = storage.get_file_state("__practice_reset_partial", source)
    if partial and boundary_inode == inode and boundary == offset:
        newline = chunk.find(b"\n")
        if newline < 0:
            return offset, b""
        return offset + newline + 1, chunk[newline + 1:]
    return offset, chunk


def _drain_numbered_rotations(
    *, source: str, path: Path, file_key: str, stored_inode: str,
    previous_offset: int, generation: int, storage: SocStorage,
    collection_mode: str, isolate_errors: bool,
    startup_boundary: StartupBoundary | None,
) -> tuple[int, int, int]:
    """Read all retained numbered rotations in chronological order."""
    candidates = []
    for candidate in path.parent.glob(f"{path.name}.[0-9]*"):
        suffix = candidate.name.removeprefix(f"{path.name}.")
        if suffix.isdecimal():
            candidates.append((int(suffix), candidate))
    candidates.sort(reverse=True)
    first = None
    for index, (_, candidate) in enumerate(candidates):
        try:
            stat = candidate.stat()
        except FileNotFoundError:
            continue
        if f"{stat.st_dev}:{stat.st_ino}" == stored_inode:
            first = index
            break
    if first is None:
        print(f"[collector] rotated inode unavailable source={source} file={file_key}", flush=True)
        return 0, 0, generation + 1

    inserted = skipped = 0
    for index in range(first, len(candidates)):
        _, candidate = candidates[index]
        with candidate.open("rb") as handle:
            stat = os.fstat(handle.fileno())
            inode = f"{stat.st_dev}:{stat.st_ino}"
            offset = previous_offset if index == first else 0
            handle.seek(offset)
            chunk = handle.read()
        offset, chunk = _skip_reset_partial(storage, source, inode, offset, chunk)
        last_nl = chunk.rfind(b"\n")
        complete_bytes = chunk[:last_nl + 1] if last_nl >= 0 else b""
        replay_before = None
        mode = collection_mode
        if startup_boundary is not None:
            if startup_boundary.file_inode == inode:
                replay_before = startup_boundary.size
            elif mode == "live":
                mode = "replay"
        records, bad = _parse_complete_bytes(
            source=source,
            record_file_key=_generation_file_key(file_key, generation),
            complete_bytes=complete_bytes,
            start_offset=offset,
            collection_mode=mode,
            isolate_errors=isolate_errors,
            replay_before_offset=replay_before,
        )
        inserted += storage.save_batch_and_advance_offset(
            source, file_key, records, offset + len(complete_bytes),
            file_inode=inode, generation=generation,
            **({"errors": bad} if bad else {}),
        )
        skipped += len(bad)
        generation += 1
    return inserted, skipped, generation


def collect_file(
    source: str,
    file_path: str | Path,
    storage: SocStorage,
    *,
    collection_mode: str = "replay",
    isolate_errors: bool = False,
    replay_before_offset: int | None = None,
    startup_boundary: StartupBoundary | None = None,
) -> CollectResult:
    """Read complete lines; handle rotation/truncation with generations and isolate corrupt lines."""
    if not isinstance(collection_mode, str) or collection_mode not in ALLOWED_INGEST_MODES:
        raise NormalizationError("invalid collection_mode")
    path = Path(file_path)
    file_key = path.name
    if hasattr(storage, "get_file_state"):
        previous_offset, stored_inode, generation = storage.get_file_state(source, file_key)
    else:
        previous_offset, stored_inode, generation = storage.get_offset(source, file_key), "", 0

    try:
        handle = path.open("rb")
    except FileNotFoundError:
        return CollectResult(
            processed_lines=0,
            inserted_records=0,
            previous_offset=previous_offset,
            new_offset=previous_offset,
        )

    rotated_inserted = 0
    rotated_skipped = 0
    with handle:
        # 이름이 같아도 파일이 교체될 수 있다. 실제로 연 파일의 정보를 확인한다.
        st = os.fstat(handle.fileno())
        file_size = st.st_size
        current_inode = f"{st.st_dev}:{st.st_ino}"
        matches_boundary = startup_boundary is not None and startup_boundary.file_inode == current_inode
        startup_size = startup_boundary.size if matches_boundary else 0
        file_changed = bool(stored_inode and current_inode != stored_inode)
        file_shrank = file_size < startup_size or (not file_changed and file_size < previous_offset)
        effective_offset = previous_offset
        if file_changed:
            rotated_inserted, rotated_skipped, generation = _drain_numbered_rotations(
                source=source,
                path=path,
                file_key=file_key,
                stored_inode=stored_inode,
                previous_offset=previous_offset,
                generation=generation,
                storage=storage,
                collection_mode=collection_mode,
                isolate_errors=isolate_errors,
                startup_boundary=startup_boundary,
            )
            effective_offset = 0
        elif file_shrank:
            generation += 1
            effective_offset = 0

        replay_before = replay_before_offset if generation == 0 else None
        if startup_boundary is not None:
            if matches_boundary and not file_shrank:
                # 시작할 때 본 파일이면, 그때 크기 앞에서 시작한 줄만 시작 전 기록이다.
                replay_before = startup_size
            elif startup_boundary.checked and not matches_boundary:
                # 시작할 때 없던 파일이면 수집기를 켠 뒤에 생긴 파일이다. 모든 줄이 새 기록이다.
                replay_before = 0
            else:
                # 시작할 때 파일 상태를 확인하지 못했거나 파일이 잘렸다면, 지금 보이는 끝까지는 조사용으로 둔다.
                replay_before = file_size

        handle.seek(effective_offset)
        chunk = handle.read()
    effective_offset, chunk = _skip_reset_partial(storage, source, current_inode, effective_offset, chunk)

    last_newline = chunk.rfind(b"\n")
    records, errors = [], []
    new_offset = effective_offset
    if last_newline >= 0:
        complete_bytes = chunk[: last_newline + 1]
        new_offset += len(complete_bytes)
        records, errors = _parse_complete_bytes(
            source=source,
            record_file_key=_generation_file_key(file_key, generation),
            complete_bytes=complete_bytes,
            start_offset=effective_offset,
            collection_mode=collection_mode,
            isolate_errors=isolate_errors,
            replay_before_offset=replay_before,
        )

    inserted = 0
    if last_newline >= 0 or current_inode != stored_inode or new_offset != previous_offset or file_shrank:
        inserted = storage.save_batch_and_advance_offset(
            source,
            file_key,
            records,
            new_offset,
            file_inode=current_inode,
            generation=generation,
            **({"errors": errors} if errors else {}),
        )

    if startup_boundary is not None and replay_before is not None:
        # 저장이 성공한 뒤에도 기준선을 남겨야 다음 읽기에서 완성되는 줄을 구분할 수 있다.
        startup_boundary.file_inode = current_inode
        startup_boundary.size = replay_before
        startup_boundary.checked = True

    return CollectResult(
        processed_lines=len(records),
        inserted_records=inserted + rotated_inserted,
        previous_offset=previous_offset,
        new_offset=new_offset,
        skipped_lines=len(errors) + rotated_skipped,
    )
