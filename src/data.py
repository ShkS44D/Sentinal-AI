"""Load and label the 43-column NSL-KDD text files."""

from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
TRAIN_PATH = ROOT / "data" / "KDDTrain+.txt"
TEST_PATH = ROOT / "data" / "KDDTest+.txt"

FEATURE_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]
COLUMNS = FEATURE_COLUMNS + ["attack", "difficulty"]
DROP_COLUMNS = ("num_outbound_cmds", "is_host_login")
MODEL_FEATURES = [name for name in FEATURE_COLUMNS if name not in DROP_COLUMNS]
CATEGORICAL = ("protocol_type", "service", "flag")

ATTACK_FAMILIES = {
    "Normal": {"normal"},
    "DoS": {"back", "land", "neptune", "pod", "smurf", "teardrop", "mailbomb", "apache2", "processtable", "udpstorm", "worm"},
    "Probe": {"ipsweep", "nmap", "portsweep", "satan", "mscan", "saint"},
    "R2L": {"ftp_write", "guess_passwd", "imap", "multihop", "phf", "spy", "warezclient", "warezmaster", "sendmail", "named", "snmpgetattack", "snmpguess", "xlock", "xsnoop", "httptunnel"},
    "U2R": {"buffer_overflow", "loadmodule", "perl", "rootkit", "ps", "sqlattack", "xterm"},
}
FAMILY_BY_ATTACK = {attack: family for family, names in ATTACK_FAMILIES.items() for attack in names}


def load_nsl_kdd(path: str | Path) -> pd.DataFrame:
    """Read an official text split, validate labels, and add binary/family targets."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Missing {path}. Run python scripts/download_data.py")
    frame = pd.read_csv(path, header=None, names=COLUMNS)
    if frame.shape[1] != 43 or frame[COLUMNS].isna().any().any():
        raise ValueError(f"Expected 43 complete NSL-KDD columns in {path}")
    frame["attack"] = frame["attack"].astype(str).str.rstrip(".").str.lower()
    unknown = sorted(set(frame["attack"]) - set(FAMILY_BY_ATTACK))
    if unknown:
        raise ValueError(f"Unmapped NSL-KDD attack labels: {', '.join(unknown)}")
    frame["label_binary"] = (frame["attack"] != "normal").astype(int)
    frame["attack_family"] = frame["attack"].map(FAMILY_BY_ATTACK)
    return frame.drop(columns=list(DROP_COLUMNS))
