"""Review Zeek JSON connection logs without fabricating NSL-KDD features."""
from io import BytesIO
import json
from ipaddress import ip_address

import pandas as pd

from src.scan import MAX_BYTES, MAX_ROWS

FIELDS = ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
          "service", "duration", "orig_bytes", "resp_bytes", "conn_state")


def read_flows(content):
    if not content.strip():
        raise ValueError("The connection log is empty.")
    if len(content) > MAX_BYTES:
        raise ValueError("Connection log exceeds the 30 MB limit.")
    try:
        records = []
        for number, line in enumerate(content.decode("utf-8-sig").splitlines(), 1):
            if not line.strip():
                continue
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError(f"Line {number}: expected a JSON connection object.")
            missing = [name for name in ("ts", "proto", "id.orig_h", "id.resp_h") if name not in record]
            if missing:
                raise ValueError(f"Line {number}: missing {', '.join(missing)}.")
            records.append({name: record.get(name) for name in FIELDS})
            if len(records) > MAX_ROWS:
                raise ValueError("Connection log exceeds 100,000 rows.")
        frame = pd.DataFrame(records, columns=FIELDS)
        if frame.empty:
            raise ValueError("No connection records found.")
        for name in ("ts", "duration", "orig_bytes", "resp_bytes", "id.orig_p", "id.resp_p"):
            values = pd.to_numeric(frame[name], errors="coerce")
            invalid = frame[name].notna() & (values.isna() | (values < 0) | (values == float("inf")))
            if name.endswith("_p"):
                invalid |= values.notna() & ((values > 65535) | (values % 1 != 0))
            if invalid.any():
                raise ValueError(f"{name}: invalid nonnegative numeric value in record {int(invalid.to_numpy().nonzero()[0][0]) + 1}.")
            frame[name] = values
        if frame[["ts", "proto", "id.orig_h", "id.resp_h"]].isna().any().any():
            raise ValueError("Timestamp, protocol and both addresses must be present.")
        for index, row in frame.iterrows():
            if not isinstance(row["proto"], str) or not row["proto"].strip():
                raise ValueError(f"Record {index + 1}: protocol must be a nonempty string.")
            for name in ("id.orig_h", "id.resp_h"):
                try:
                    ip_address(row[name])
                except (ValueError, TypeError):
                    raise ValueError(f"Record {index + 1}: {name} must be a valid IP address.") from None
        frame["timestamp_utc"] = pd.to_datetime(frame["ts"], unit="s", utc=True, errors="coerce")
        if frame["timestamp_utc"].isna().any():
            raise ValueError("A timestamp is outside the supported date range.")
        return frame
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Use UTF-8 Zeek JSON logs, one object per line: {exc}") from exc


def flow_csv(frame):
    buffer = BytesIO()
    frame.to_csv(buffer, index=False)
    return buffer.getvalue()
