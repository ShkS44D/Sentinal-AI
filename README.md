# Sentinel IDS

Sentinel IDS is a Streamlit demonstration of binary network connection
classification using the NSL-KDD benchmark. It predicts **normal** or
**anomaly** for stored test examples. It does not capture live traffic or
identify a specific attack type.

## Measured performance

**Model Insights** includes a reliability report with errors by recorded attack
family, threshold trade-offs and probability bins. Alert details offer an
optional model sensitivity comparison against training reference values.
**Flow Import** reviews real Zeek JSON connection logs without inventing missing
NSL-KDD features or assigning unsupported scores. **Sample Detection** includes
a guided first scan.

The interface uses a blue-and-white theme with an **Overview**, consistent page
headings and clearly labeled scan steps. Select **Try sample scan** from the
Overview or Batch Scan to process the bundled real test rows in one click;
these scans are tagged as demo activity. Restart Streamlit after updating the
theme configuration.

Optional administrator/analyst accounts, container setup and automated GitHub
checks are documented in [docs/OPERATIONS.md](docs/OPERATIONS.md).

<!-- METRICS:START -->
Random Forest on **NSL-KDD KDDTest+** (22,544 rows), trained on **KDDTrain+** (125,973 rows):

| Accuracy | Precision | Recall | F1 | False positive rate | ROC-AUC | PR-AUC |
|---:|---:|---:|---:|---:|---:|---:|
| 76.37% | 96.59% | 60.62% | 74.49% | 2.83% | 96.56% | 96.53% |

Training cross-validation F1 is 99.88%, while the official test F1 is 74.49%. Official test recall is 60.62%; the model misses many anomalies in this split.
<!-- METRICS:END -->

These numbers are generated from [reports/metrics.json](reports/metrics.json)
by `python -m src.train`. See [the full report](reports/metrics.md) for the
five-fold training comparison, confusion matrix and evaluation plots.
The official test split has a different distribution and attack types absent
from training; the gap shows that training-fold scores do not represent
performance on the harder official test set.

The legacy 500-row validation CSV overlaps the training split in **all 500
rows**. Its perfect score is not independent validation; see
[reports/notes.md](reports/notes.md).

## Run the app

Use Python 3.10 or newer. From the project root:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python scripts/download_data.py
streamlit run app/main.py
```

**Manual Scan** lets you enter all 39
features with training-based ranges or load a real test example. **Batch Scan**
accepts headed CSV files or original NSL-KDD text files, validates them, and
scans up to 100,000 rows. It includes threshold and severity controls,
filters, a results CSV, and a one-page HTML summary. Use
[`data/sample_traffic.csv`](data/sample_traffic.csv) to try the full workflow.
Sample Detection still selects one test row and hides its ground truth until
requested. AI Analytics shows global Random Forest feature importance.

Batch CSVs need the 39 feature columns listed in the downloadable template.
`protocol_type`, `service`, and `flag` may contain raw names or training encoder
integers; the page explains which form it detected. Optional `label_binary` or
`class` columns use 0 for normal and 1 for anomaly. An optional `attack` column
uses NSL-KDD attack names. Uploaded labels enable live precision, recall, and
false-positive counts when the threshold changes. Without labels, the page
shows prediction counts only. Severity bands classify anomaly probability;
their cutoffs are adjustable and separate from the anomaly decision threshold.

## Saved history and investigations

Every Manual Scan and Batch Scan is saved to the local SQLite database at
`data/sentinel.db` (Git ignored). Sample Detection also saves its real NSL-KDD
test example as a clearly tagged demo scan. The **Dashboard** now reads only
saved scan data: totals, anomaly rate, open alerts, time series, top services
and protocols, and recent activity. It shows an empty state before the first
scan. Model evaluation remains in the generated reports rather than being
mixed with operational dashboard counts.

The **Alerts** page lists saved anomaly predictions with search, filters,
sorting and pagination. Open an alert to see all feature values, descriptive
feature observations, status history and analyst notes. The observations are
simple rules based on values; they are not explanations of the model's internal
decision. Analysts can update several alerts together and export filtered
alerts to CSV. Statuses are New, Investigating, Confirmed, False Positive and
Resolved. Saved threshold changes update stored classifications without
rerunning the model.

**Settings** shows database size, exports/imports a ZIP of the four database
tables as CSV, deletes tagged demo scans, or deletes all scan data after typed
confirmation. A minimal deletion receipt remains in the audit trail. Database
import replaces current local data and requires confirmation. See
[docs/HISTORY.md](docs/HISTORY.md) for schema and backup details.

## Reproduce training and reports

```powershell
python -m src.train
```

The command fits preprocessing on training data only, compares Random Forest,
Logistic Regression and Histogram Gradient Boosting with stratified five-fold
cross-validation, fits the Random Forest on full `KDDTrain+`, and evaluates it
once on `KDDTest+`. It regenerates `models/v1/`, `reports/metrics.json`,
`reports/metrics.md`, the evaluation plots and this README's metric table.
Random seed: 42. See [docs/DATA.md](docs/DATA.md) for source URLs, hashes,
column definitions and attack-family mapping.

For tests and lint:

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest
ruff check .
```

## Project layout

```text
app/                 Streamlit pages and entry point
src/                 Data, model, scan, persistence, investigation and reports
scripts/             Data download and legacy overlap check
data/                Downloaded NSL-KDD text files (Git ignored), tracked sample CSV
                      and local SQLite history (Git ignored)
models/v1/           Versioned joblib artifacts and metadata
models/legacy/       Original pickle artifacts and 500-row sample
reports/             Generated test metrics, notes and figures
notebooks/           Lightweight exploratory analysis
docs/                Dataset and feature documentation
tests/               Automated checks
```

## Limitations and safety

NSL-KDD is based on old network traffic. This binary model should not be
treated as a deployed intrusion prevention system. It has no packet capture,
sensor integration, blocking or mitigation. The official test results show
substantial missed anomalies. Model confidence is not a calibrated guarantee.

Joblib and pickle files can execute code when loaded. The app loads only the
bundled artifacts; never replace them with files from an untrusted source.
The original pickle files remain in `models/legacy/` for reproducibility.

## Repository and license

[GitHub repository](https://github.com/ShkS44D/Sentinal-AI). Licensed under
MIT; copyright Muhammad Saad Ahmed. See [LICENSE](LICENSE).
