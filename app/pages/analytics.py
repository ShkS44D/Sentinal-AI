"""Global model feature importance."""
import pandas as pd
import plotly.express as px
import streamlit as st

def render(assets):
    st.title("📈 Model Insights")
    st.write("Global feature importance for the saved binary normal versus anomaly classifier.")
    st.caption("These scores describe the model overall; they do not explain an individual prediction or identify an attack type.")
    frame = pd.DataFrame(
        {"Feature": assets.feature_names, "Importance": assets.model.feature_importances_}
    ).nlargest(10, "Importance").sort_values("Importance")
    figure = px.bar(
        frame, x="Importance", y="Feature", orientation="h", template="plotly_dark",
        color="Importance", color_continuous_scale="Blues",
    )
    figure.update_layout(showlegend=False)
    st.plotly_chart(figure, use_container_width=True)
    st.caption("Measured test performance and evaluation plots are in reports/metrics.md and reports/figures/.")
