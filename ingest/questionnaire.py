"""Parse the filled questionnaire CSV exported by the CIDA SaaS intake form.

Expected CSV columns (flexible - case-insensitive, fuzzy matched):
    control_id, answer[, evidence_ref, notes]

Acceptable answers per control response_type:
    yes_no:       "yes"/"no"/"y"/"n"/"true"/"false"/1/0
    scale_1_5:    integer 1-5
    multi_select: pipe- or semicolon-separated list of option strings
    evidence:     a URL or "uploaded"/"provided"

The parser also accepts the wide format used by Excel exports (one row per org,
one column per control_id) - autodetected.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from catalog.loader import load_catalog
from models import Control, ControlResponse, QuestionnaireResponses


YES_VALUES = {"yes", "y", "true", "t", "1", 1, True, "implemented", "in place", "compliant"}
NO_VALUES = {"no", "n", "false", "f", "0", 0, False, "not implemented", "not in place", "non-compliant", ""}


def _normalize(s: Any) -> str:
    if s is None:
        return ""
    return str(s).strip().lower()


def _score_yes_no(answer: Any) -> float:
    a = _normalize(answer)
    if a in {str(v).lower() for v in YES_VALUES}:
        return 100.0
    if a in {str(v).lower() for v in NO_VALUES}:
        return 0.0
    # Try numeric (some sheets store 1/0, or 1-5 scale answers on yes_no controls)
    try:
        n = float(a)
    except (ValueError, TypeError):
        return 0.0
    # Map any positive number ≥ 3 (on a 1-5 scale) to yes; otherwise no.
    return 100.0 if n >= 3 else 0.0


def _score_scale_1_5(answer: Any) -> float:
    # Booleans tolerated: True → 5 (full), False → 1 (none).
    if isinstance(answer, bool):
        return 100.0 if answer else 0.0
    # Pure numeric path
    try:
        n = float(answer)
        n = max(1, min(5, n))
        # 1 -> 0, 2 -> 25, 3 -> 50, 4 -> 75, 5 -> 100
        return (n - 1) * 25.0
    except (ValueError, TypeError):
        pass
    # Non-numeric string: try yes/no fallback (helps when CSVs mix styles)
    a = _normalize(answer)
    if a in {"yes", "y", "true", "implemented", "in place", "compliant"}:
        return 100.0
    if a in {"no", "n", "false", "not implemented", "not in place", "non-compliant"}:
        return 0.0
    return 0.0


def _score_multi_select(answer: Any, control: Control) -> float:
    if not control.options:
        return 0.0
    selected = [s.strip().lower() for s in str(answer).replace(";", "|").split("|") if s.strip()]
    options_lower = [o.lower() for o in control.options]
    matched = sum(1 for s in selected if s in options_lower)
    return 100.0 * matched / max(len(options_lower), 1)


def _score_evidence(answer: Any) -> float:
    a = _normalize(answer)
    if not a:
        return 0.0
    if any(token in a for token in ["http", "uploaded", "provided", "attached"]):
        return 100.0
    return 50.0


def _score_response(raw: Any, control: Control) -> float:
    match control.response_type:
        case "yes_no":
            return _score_yes_no(raw)
        case "scale_1_5":
            return _score_scale_1_5(raw)
        case "multi_select":
            return _score_multi_select(raw, control)
        case "evidence":
            return _score_evidence(raw)
        case _:
            return 0.0


def _detect_layout(df: pd.DataFrame) -> str:
    """Return 'long' (control_id+answer columns) or 'wide' (one column per control)."""
    cols_lower = [c.strip().lower() for c in df.columns]
    if "control_id" in cols_lower and "answer" in cols_lower:
        return "long"
    catalog = load_catalog()
    catalog_ids = {c.control_id.lower() for c in catalog.controls}
    if any(c in catalog_ids for c in cols_lower):
        return "wide"
    return "long"  # default


def parse_questionnaire_csv(csv_path: str | Path, org_id: str | None = None) -> QuestionnaireResponses:
    """Parse a questionnaire CSV into normalized responses."""
    csv_path = Path(csv_path)
    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
    df.columns = [c.strip() for c in df.columns]

    catalog = load_catalog()
    catalog_by_id = {c.control_id: c for c in catalog.controls}

    layout = _detect_layout(df)
    responses: list[ControlResponse] = []

    if layout == "long":
        col_map = {c.lower(): c for c in df.columns}
        cid_col = col_map.get("control_id", "control_id")
        ans_col = col_map.get("answer", "answer")
        ev_col = col_map.get("evidence_ref")
        note_col = col_map.get("notes")
        for _, row in df.iterrows():
            cid = str(row[cid_col]).strip()
            if not cid or cid not in catalog_by_id:
                continue
            control = catalog_by_id[cid]
            raw = row[ans_col]
            score = _score_response(raw, control)
            responses.append(ControlResponse(
                control_id=cid,
                raw_answer=str(raw),
                score=score,
                evidence_ref=str(row[ev_col]).strip() if ev_col and pd.notna(row[ev_col]) else None,
                notes=str(row[note_col]).strip() if note_col and pd.notna(row[note_col]) else None,
            ))
    else:  # wide
        # one row expected; use first row
        if len(df) == 0:
            raise ValueError("Empty questionnaire CSV")
        row = df.iloc[0]
        for cid_col in df.columns:
            cid = cid_col.strip()
            if cid not in catalog_by_id:
                continue
            control = catalog_by_id[cid]
            raw = row[cid_col]
            score = _score_response(raw, control)
            responses.append(ControlResponse(
                control_id=cid, raw_answer=str(raw), score=score
            ))

    return QuestionnaireResponses(
        org_id=org_id or csv_path.stem,
        submitted_at=datetime.now(tz=timezone.utc),
        responses=responses,
    )
