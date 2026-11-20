from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .models import NormalizedEvent, RawLogRecord
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
) -> tuple[list[tuple[RawLogRecord, NormalizedEvent]], int]:
    """Parse complete lines; when isolate_errors=True, quarantine invalid lines without stalling."""
    records: list[tuple[RawLogRecord, NormalizedEvent]] = []
    skipped = 0
    cursor = start_offset
    for raw_bytes in complete_bytes.splitlines(keepends=True):
        line_offset = cursor
        cursor += len(raw_bytes)
        try:
            decoded = raw_bytes.decode("utf-8")
            if not decoded.strip():
                continue
            raw_rec, norm_evt = normalize_log_line(
                decoded,
                source=source,
                file_path=record_file_key,
                line_offset=line_offset,
                collection_mode=collection_mode,
            )
            records.append((raw_rec, norm_evt))
        except Exception as exc:
            if not isolate_errors:
                raise
            skipped += 1
            print(
                f"[collector] quarantined invalid line source={source} file={record_file_key} offset={line_offset}: {type(exc).__name__}",
                flush=True,
            )
    return records, skipped


def _drain_rotated_tail(
    *,
    source: str,
    path: Path,
    file_key: str,
    stored_inode: str,
    previous_offset: int,
    generation: int,
    storage: SocStorage,
    collection_mode: str,
    isolate_errors: bool = False,
) -> tuple[int, int]:
    """Drain remaining unread lines from rotated sibling `.1` matching stored_inode."""
    rotated = path.with_name(f"{path.name}.1")
    if not rotated.exists():
        return 0, 0
    try:
        rst = rotated.stat()
    except OSError:
        return 0, 0
    if f"{rst.st_dev}:{rst.st_ino}" != stored_inode or rst.st_size <= previous_offset:
        return 0, 0
    with rotated.open("rb") as handle:
        handle.seek(previous_offset)
        chunk = handle.read()
    last_nl = chunk.rfind(b"\n")
    if last_nl == -1:
        return 0, 0
    complete_bytes = chunk[: last_nl + 1]
    prev_key = _generation_file_key(file_key, generation)
    records, skipped = _parse_complete_bytes(
        source=source,
        record_file_key=prev_key,
        complete_bytes=complete_bytes,
        start_offset=previous_offset,
        collection_mode=collection_mode,
        isolate_errors=isolate_errors,
    )
    inserted = 0
    if records:
        inserted = storage.save_batch_and_advance_offset(
            source,
            file_key,
            records,
            previous_offset + len(complete_bytes),
            file_inode=stored_inode,
            generation=generation,
        )
    return inserted, skipped


def collect_file(
    source: str,
    file_path: str | Path,
    storage: SocStorage,
    *,
    collection_mode: str = "replay",
    isolate_errors: bool = False,
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

    if not path.exists():
        return CollectResult(
            processed_lines=0,
            inserted_records=0,
            previous_offset=previous_offset,
            new_offset=previous_offset,
        )

    st = path.stat()
    file_size = st.st_size
    current_inode = f"{st.st_dev}:{st.st_ino}"

    rotated_inserted = 0
    rotated_skipped = 0
    if stored_inode and current_inode != stored_inode:
        rotated_inserted, rotated_skipped = _drain_rotated_tail(
            source=source,
            path=path,
            file_key=file_key,
            stored_inode=stored_inode,
            previous_offset=previous_offset,
            generation=generation,
            storage=storage,
            collection_mode=collection_mode,
            isolate_errors=isolate_errors,
        )
        generation += 1
        effective_offset = 0
    elif file_size < previous_offset:
        generation += 1
        effective_offset = 0
    else:
        effective_offset = previous_offset

    with path.open("rb") as handle:
        handle.seek(effective_offset)
        chunk = handle.read()

    last_newline = chunk.rfind(b"\n")
    if last_newline == -1:
        if current_inode != stored_inode or effective_offset != previous_offset:
            storage.save_batch_and_advance_offset(
                source,
                file_key,
                [],
                effective_offset,
                file_inode=current_inode,
                generation=generation,
            )
        return CollectResult(
            processed_lines=0,
            inserted_records=rotated_inserted,
            previous_offset=previous_offset,
            new_offset=effective_offset,
            skipped_lines=rotated_skipped,
        )

    complete_bytes = chunk[: last_newline + 1]
    new_offset = effective_offset + len(complete_bytes)
    record_file_key = _generation_file_key(file_key, generation)
    records, skipped = _parse_complete_bytes(
        source=source,
        record_file_key=record_file_key,
        complete_bytes=complete_bytes,
        start_offset=effective_offset,
        collection_mode=collection_mode,
        isolate_errors=isolate_errors,
    )

    inserted = storage.save_batch_and_advance_offset(
        source,
        file_key,
        records,
        new_offset,
        file_inode=current_inode,
        generation=generation,
    )
    return CollectResult(
        processed_lines=len(records),
        inserted_records=inserted + rotated_inserted,
        previous_offset=previous_offset,
        new_offset=new_offset,
        skipped_lines=skipped + rotated_skipped,
    )
