# NSL-KDD evaluation

Random Forest trained on 125,973 KDDTrain+ rows; evaluated once on 22,544 KDDTest+ rows. Seed: 42.

## Five-fold training cross-validation (mean)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---:|---:|---:|---:|---:|
| Random Forest | 0.9989 | 0.9994 | 0.9982 | 0.9988 | 1.0000 |
| Logistic Regression | 0.9541 | 0.9619 | 0.9387 | 0.9501 | 0.9905 |
| Histogram Gradient Boosting | 0.9988 | 0.9990 | 0.9984 | 0.9987 | 1.0000 |

## Official test split: Random Forest

- Accuracy: 0.7637
- Precision: 0.9659
- Recall: 0.6062
- F1: 0.7449
- False Positive Rate: 0.0283
- Roc Auc: 0.9656
- Pr Auc: 0.9653
- Confusion matrix (TN, FP, FN, TP): 9436, 275, 5053, 7780

The official test split includes attack types absent from training and has a different distribution. Cross-validation scores should not be substituted for test scores.
