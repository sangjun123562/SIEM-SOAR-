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


def collect_file(
    source: str,
    file_path: str | Path,
    storage: SocStorage,
    *,
    collection_mode: str = "replay",
) -> CollectResult:
    """Read complete lines; imported files default to replay, even if labeled live.

    Only an independently verified producer volume may be configured as live.
    """
    if not isinstance(collection_mode, str) or collection_mode not in ALLOWED_INGEST_MODES:
        raise NormalizationError("invalid collection_mode")
    path = Path(file_path)
    file_key = path.name
    previous_offset = storage.get_offset(source, file_key)

    if not path.exists():
        return CollectResult(
            processed_lines=0,
            inserted_records=0,
            previous_offset=previous_offset,
            new_offset=previous_offset,
        )

    file_size = path.stat().st_size
    effective_offset = 0 if file_size < previous_offset else previous_offset

    with path.open("rb") as handle:
        handle.seek(effective_offset)
        chunk = handle.read()

    last_newline = chunk.rfind(b"\n")
    if last_newline == -1:
        # No complete newline-terminated line yet; leave offset unchanged.
        return CollectResult(
            processed_lines=0,
            inserted_records=0,
            previous_offset=previous_offset,
            new_offset=effective_offset,
        )

    complete_bytes = chunk[: last_newline + 1]
    new_offset = effective_offset + len(complete_bytes)

    records: list[tuple[RawLogRecord, NormalizedEvent]] = []
    cursor = effective_offset
    for raw_bytes in complete_bytes.splitlines(keepends=True):
        line_offset = cursor
        cursor += len(raw_bytes)
        decoded = raw_bytes.decode("utf-8")
        if not decoded.strip():
            continue
        raw_rec, norm_evt = normalize_log_line(
            decoded,
            source=source,
            file_path=file_key,
            line_offset=line_offset,
            collection_mode=collection_mode,
        )
        records.append((raw_rec, norm_evt))

    inserted = storage.save_batch_and_advance_offset(source, file_key, records, new_offset)
    return CollectResult(
        processed_lines=len(records),
        inserted_records=inserted,
        previous_offset=previous_offset,
        new_offset=new_offset,
    )
