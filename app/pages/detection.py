"""Sample-based detection demonstration."""
import pandas as pd
import streamlit as st
from src.data import TEST_PATH, load_nsl_kdd
from src.history import save_scan
from src.prediction import PreprocessingError, predict
from app.ui import page_header

SAMPLES = TEST_PATH

def render(assets):
    page_header("Sample Detection", "Compare a model prediction with a recorded official test example.")
    st.info("Demo: choose a stored NSL-KDD official test row and run the binary classifier. This is not live network capture.")
    with st.expander("First scan: a three-step guide", expanded=True):
        st.write("1. Choose a sample to inspect a real recorded test connection.")
        st.write("2. Run scan to predict Normal or Anomaly and save a clearly tagged demo record.")
        st.write("3. Reveal the recorded label and compare it with the prediction. Open Alerts to investigate a predicted anomaly.")
        st.caption("A correct sample prediction does not establish overall reliability. See AI Analytics for the full official test results.")
    if st.button("Choose random sample"):
        try:
            st.session_state["current_sample"] = load_nsl_kdd(SAMPLES).sample(1).iloc[0]
            st.session_state.pop("last_result", None)
        except (OSError, ValueError, pd.errors.ParserError) as exc:
            st.error(f"Could not read sample data: {exc}")
            return
    row = st.session_state.get("current_sample")
    if row is None:
        return
    columns = ("duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes")
    st.subheader("Connection features")
    st.dataframe(pd.DataFrame([row[list(columns)]]), use_container_width=True)
    unseen = [name for name, encoder in assets.encoders.items() if row[name] not in encoder.classes_]
    if unseen:
        st.caption(
            "This official test row has categories unseen during training: "
            + ", ".join(unseen)
            + ". They are encoded as -1, as in the evaluation pipeline."
        )
    if st.button("Run scan"):
        try:
            label, confidence = predict(row.to_dict(), assets, unknown_policy="encode")
        except PreprocessingError as exc:
            st.error(str(exc))
        else:
            probability = confidence if label == 1 else 1 - confidence
            try:
                save_scan(
                    [{"features": row[assets.feature_names].to_dict(),
                      "probability": probability, "family": row["attack_family"]}],
                    source="manual", filename="KDDTest+ sample", is_demo=True,
                )
            except (OSError, ValueError) as exc:
                st.error(f"Prediction succeeded, but the scan could not be saved: {exc}")
                return
            st.session_state["last_result"] = (label, confidence)
    result = st.session_state.get("last_result")
    if result is not None:
        label, confidence = result
        if label == 1:
            st.error(f"Anomaly predicted · model confidence {confidence:.1%}")
        else:
            st.success(f"Normal predicted · model confidence {confidence:.1%}")
    if st.toggle("Reveal ground truth", value=False):
        st.write("Recorded label:", "Anomaly" if int(row["label_binary"]) == 1 else "Normal")
