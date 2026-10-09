# Reliability, accounts and deployment

## Measured reliability

Run `python -m src.reliability` after downloading the official splits, and
after each model retraining. This evaluates the saved model on KDDTest+ and
writes `reports/reliability.json`, including model and test-file SHA-256 hashes.
The report includes binary errors by **recorded** family, threshold trade-offs,
probability bins and Brier score. Families are not multiclass predictions.
Threshold tuning on this test report would consume the independence of the test
set; use a separate training validation split for actual tuning or calibration.

Alert sensitivity replaces one feature at a time with its training median
(numeric) or mode (categorical). It reports the difference in raw anomaly
probability. This is an exploratory comparison, not causal attribution; it can
create unrealistic combinations of correlated features. The original feature
heuristics remain separately labeled.

## Accounts

Without `SENTINEL_USERS_FILE`, the app displays **Local demo mode** and permits
local administrator actions. Configure accounts before exposing the server:

```powershell
python scripts/create_user.py saad --role admin
python scripts/create_user.py analyst1 --role analyst
$env:SENTINEL_USERS_FILE = (Resolve-Path .streamlit/users.json).Path
python -m streamlit run app/main.py
```

The interactive script stores salted PBKDF2-SHA256 hashes, not plaintext
passwords. The default account file is gitignored. Keep it readable only by the
server operator. Administrators can manage data in Settings; analysts can scan,
review alerts and write notes, but cannot access Settings. Sessions expire after
one hour. Sign-out clears session data. Account removal or password changes
invalidate the next request from an existing session.

Failed login attempts have a short session-level cooldown. This is basic local
authentication, without MFA, recovery, centralized identity or distributed
rate limiting. For public hosting, place it behind HTTPS and an identity-aware
gateway; do not rely on this cooldown as brute-force protection. Existing audit
events record actions and timestamps, not authenticated actor identities.

## Zeek connection logs

Flow Import accepts UTF-8 JSON lines from Zeek `conn.log` (30 MB / 100,000
records maximum). Timestamp, protocol and source/destination addresses are
required. Optional fields remain blank. Numeric fields and ports are validated.
It shows actual connection counts, filters protocols and exports CSV.

See the [Zeek connection log documentation](https://docs.zeek.org/en/current/reference/logs/conn.html).
These logs lack content features and NSL-KDD window statistics needed by the
39-feature model. Therefore this importer performs review only, does not insert
scans or alerts, and does not fill unavailable features with zero or score them.
Live capture and a separately trained flow-compatible model are future work.

## Container

```powershell
docker build -t sentinel-ids .
docker run --rm -p 127.0.0.1:8501:8501 -v sentinel-history:/history sentinel-ids
```

This runs as a non-root user and retains scan history in a named volume. The
build downloads the checksum-verified benchmark splits, so it requires network
access. Secrets and local scan history are excluded from the build context.
For accounts, mount your private users file read-only at `/config/users.json`
and add `-e SENTINEL_USERS_FILE=/config/users.json`. Make the mounted file
readable by the container user. Open http://localhost:8501.

Dependencies are pinned; the Python base tag is versioned but not digest pinned.
GitHub Actions installs dependencies, downloads the verified data and runs tests
and Ruff on pushes and pull requests. Container execution needs local Docker.
