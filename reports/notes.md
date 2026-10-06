# Legacy validation overlap

The bundled `models/legacy/validation_with_labels.csv` contains 500 rows.
All **500 of 500** rows exactly match a row in `KDDTrain+.txt` after applying
the bundled legacy categorical encoders and comparing all 39 features plus the
binary label (numeric values rounded to eight decimal places for comparison).
Run `python -m scripts.check_overlap` to reproduce the check.

Consequently, the old 100% score on that sample is **training-data overlap**,
not independent validation performance. Performance claims must use the
official `KDDTest+.txt` evaluation in `reports/metrics.json`.
