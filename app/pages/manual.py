"""Manual entry of 39 NSL-KDD connection features."""

import streamlit as st

from src.data import MODEL_FEATURES, TEST_PATH, load_nsl_kdd
from src.feature_info import GROUPS, HINTS, training_category_defaults, training_statistics
from src.history import reclassify_scan, save_scan
from src.prediction import PreprocessingError, preprocess
from src.scan import classify


@st.cache_data(show_spinner=False)
def _examples():
    data = load_nsl_kdd(TEST_PATH)
    stats = training_statistics()
    usable = data.copy()
    for name, limits in stats.items():
        usable = usable[usable[name].between(limits["min"], limits["max"])]
    normal = usable[usable["label_binary"] == 0].iloc[0]
    attack = usable[usable["label_binary"] == 1].iloc[0]
    return {
        "Normal": {"features": normal[MODEL_FEATURES].to_dict(), "family": normal["attack_family"]},
        "Attack": {"features": attack[MODEL_FEATURES].to_dict(), "family": attack["attack_family"]},
    }


def _initial_values(assets, stats):
    categories = training_category_defaults()
    for name in assets.feature_names:
        key = f"manual_{name}"
        if key not in st.session_state:
            if name in assets.encoders:
                st.session_state[key] = categories[name]
            else:
                value = stats[name]["default"]
                st.session_state[key] = int(value) if stats[name]["integer"] else float(value)


def render(assets):
    st.title("✍️ Manual Scan")
    st.caption("Enter all 39 NSL-KDD connection features. Input ranges and defaults come from KDDTrain+.")
    try:
        stats = training_statistics()
    except (OSError, ValueError) as exc:
        st.error(f"Cannot load training feature ranges: {exc}")
        return
    _initial_values(assets, stats)
    left, right = st.columns(2)
    for column, family in ((left, "Normal"), (right, "Attack")):
        if column.button(f"Load example {family.lower()}"):
            try:
                example = _examples()[family]
            except (OSError, ValueError, IndexError) as exc:
                st.error(f"Cannot load test example: {exc}")
                return
            for name, value in example["features"].items():
                st.session_state[f"manual_{name}"] = value
            st.session_state["manual_example_features"] = example["features"]
            st.session_state["manual_example_family"] = example["family"]
            st.session_state.pop("manual_result", None)
            st.rerun()
    with st.form("manual_scan"):
        for group, names in GROUPS.items():
            with st.expander(group, expanded=group == "Basic connection"):
                columns = st.columns(3)
                for index, name in enumerate(names):
                    label = name.replace("_", " ").title()
                    key = f"manual_{name}"
                    with columns[index % 3]:
                        if name in assets.encoders:
                            st.selectbox(
                                label, options=list(assets.encoders[name].classes_),
                                key=key, help=HINTS[name],
                            )
                        else:
                            limits = stats[name]
                            st.number_input(
                                label,
                                min_value=int(limits["min"]) if limits["integer"] else limits["min"],
                                max_value=int(limits["max"]) if limits["integer"] else limits["max"],
                                step=1 if limits["integer"] else 0.01,
                                key=key, help=HINTS[name],
                            )
        submitted = st.form_submit_button("Run manual scan", type="primary")
    if submitted:
        row = {name: st.session_state[f"manual_{name}"] for name in assets.feature_names}
        try:
            probability = float(assets.model.predict_proba(preprocess(row, assets))[0, 1])
        except (PreprocessingError, ValueError) as exc:
            st.error(f"Cannot scan these values: {exc}")
        else:
            is_example = row == st.session_state.get("manual_example_features")
            try:
                scan_id = save_scan(
                    [{"features": row, "probability": probability,
                      "family": st.session_state.get("manual_example_family") if is_example else None}],
                    source="manual", filename="KDDTest+ example" if is_example else None,
                    threshold=st.session_state.get("manual_threshold", 0.5),
                    is_demo=is_example,
                )
            except (OSError, ValueError) as exc:
                st.error(f"Prediction succeeded, but the scan could not be saved: {exc}")
                return
            st.session_state["manual_result"] = probability
            st.session_state["manual_scan_id"] = scan_id
    if "manual_result" in st.session_state:
        threshold = st.slider("Anomaly threshold", 0.0, 1.0, 0.5, 0.01, key="manual_threshold")
        reclassify_scan(st.session_state["manual_scan_id"], threshold)
        probability = st.session_state["manual_result"]
        prediction, _ = classify([probability], threshold)
        st.metric("Anomaly probability", f"{probability:.1%}")
        if prediction[0] == "Anomaly":
            st.error("Anomaly predicted")
        else:
            st.success("Normal predicted")
