"""NSL-KDD feature groups, plain-language hints, and training ranges."""

from functools import lru_cache

from src.data import CATEGORICAL, MODEL_FEATURES, TRAIN_PATH, load_nsl_kdd

GROUPS = {
    "Basic connection": (
        "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
        "land", "wrong_fragment", "urgent",
    ),
    "Content": (
        "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell",
        "su_attempted", "num_root", "num_file_creations", "num_shells",
        "num_access_files", "is_guest_login",
    ),
    "Traffic / time window": (
        "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
        "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    ),
    "Host-based": (
        "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
        "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
        "dst_host_srv_serror_rate", "dst_host_rerror_rate",
        "dst_host_srv_rerror_rate",
    ),
}

HINTS = {
    "duration": "Length of the connection in seconds.",
    "protocol_type": "Network protocol used by the connection.",
    "service": "Destination network service recorded by NSL-KDD.",
    "flag": "Connection status flag recorded by NSL-KDD.",
    "src_bytes": "Bytes sent from source to destination.",
    "dst_bytes": "Bytes sent from destination to source.",
    "land": "1 if source and destination addresses and ports match; otherwise 0.",
    "wrong_fragment": "Number of malformed IP fragments.",
    "urgent": "Number of urgent packets.",
    "hot": "Number of suspicious content indicators.",
    "num_failed_logins": "Number of failed login attempts.",
    "logged_in": "1 if login succeeded; otherwise 0.",
    "num_compromised": "Number of compromised conditions observed.",
    "root_shell": "1 if a root shell was obtained; otherwise 0.",
    "su_attempted": "Number or status of su command attempts.",
    "num_root": "Number of root-level accesses.",
    "num_file_creations": "Number of file creation operations.",
    "num_shells": "Number of shell prompts invoked.",
    "num_access_files": "Number of operations on access-control files.",
    "is_guest_login": "1 if login used a guest account; otherwise 0.",
    "count": "Connections to the same destination host in the recent time window.",
    "srv_count": "Connections to the same service in the recent time window.",
    "serror_rate": "Share of recent host connections with SYN errors.",
    "srv_serror_rate": "Share of recent service connections with SYN errors.",
    "rerror_rate": "Share of recent host connections with REJ errors.",
    "srv_rerror_rate": "Share of recent service connections with REJ errors.",
    "same_srv_rate": "Share of recent host connections using this service.",
    "diff_srv_rate": "Share of recent host connections using other services.",
    "srv_diff_host_rate": "Share of recent service connections to other hosts.",
    "dst_host_count": "Recent connections to this destination host.",
    "dst_host_srv_count": "Recent connections to this destination host and service.",
    "dst_host_same_srv_rate": "Share of destination-host connections using this service.",
    "dst_host_diff_srv_rate": "Share of destination-host connections using other services.",
    "dst_host_same_src_port_rate": "Share of destination-host connections with the same source port.",
    "dst_host_srv_diff_host_rate": "Share of host-service connections from other source hosts.",
    "dst_host_serror_rate": "Share of destination-host connections with SYN errors.",
    "dst_host_srv_serror_rate": "Share of host-service connections with SYN errors.",
    "dst_host_rerror_rate": "Share of destination-host connections with REJ errors.",
    "dst_host_srv_rerror_rate": "Share of host-service connections with REJ errors.",
}


@lru_cache(maxsize=1)
def training_statistics():
    """Observed min, max and median from KDDTrain+ only."""
    training = load_nsl_kdd(TRAIN_PATH)
    stats = {}
    for name in MODEL_FEATURES:
        if name in CATEGORICAL:
            continue
        values = training[name]
        stats[name] = {
            "min": float(values.min()), "max": float(values.max()),
            "default": float(values.median()), "integer": bool(values.dtype.kind in "iu"),
        }
    return stats


@lru_cache(maxsize=1)
def training_category_defaults():
    training = load_nsl_kdd(TRAIN_PATH)
    return {name: str(training[name].mode().iloc[0]) for name in CATEGORICAL}


def feature_label(name):
    """Expand benchmark abbreviations for analyst-facing controls."""
    words = name.split("_")
    replacements = {"src": "source", "dst": "destination", "srv": "service",
                    "num": "number of", "serror": "SYN error", "rerror": "rejection error",
                    "su": "superuser"}
    return " ".join(replacements.get(word, word) for word in words).capitalize()
