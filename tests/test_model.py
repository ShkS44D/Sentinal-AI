import importlib
import pytest

from src.data import MODEL_FEATURES, TRAIN_PATH, load_nsl_kdd
from src.model import ModelLoadError, load_assets
from src.prediction import PreprocessingError, predict, preprocess

def test_model_loads():
    assets = load_assets()
    assert len(assets.feature_names) == 39
    assert assets.scaler.n_features_in_ == 39
    assert set(assets.encoders) == {"protocol_type", "service", "flag"}


def test_raw_text_round_trip_matches_encoded_sample():
    assets = load_assets()
    raw = load_nsl_kdd(TRAIN_PATH).iloc[0][MODEL_FEATURES].to_dict()
    encoded = raw.copy()
    for name, encoder in assets.encoders.items():
        encoded[name] = int(encoder.transform([raw[name]])[0])
    assert (preprocess(raw, assets) == preprocess(encoded, assets)).all()
    assert predict(raw, assets) == predict(encoded, assets)


def test_unseen_category_has_clear_message():
    assets = load_assets()
    raw = load_nsl_kdd(TRAIN_PATH).iloc[0][MODEL_FEATURES].to_dict()
    raw["protocol_type"] = "unknown_protocol"
    with pytest.raises(PreprocessingError, match="Unknown protocol_type: unknown_protocol"):
        preprocess(raw, assets)


def test_missing_model_file_has_clear_message(monkeypatch, tmp_path):
    import src.model as model_module

    monkeypatch.setattr(model_module, "MODEL_DIR", tmp_path)
    model_module.load_assets.cache_clear()
    with pytest.raises(ModelLoadError, match="Cannot load model.joblib"):
        model_module.load_assets()
    model_module.load_assets.cache_clear()


def test_app_modules_import():
    for name in ("app.main", "app.pages.dashboard", "app.pages.detection", "app.pages.analytics"):
        importlib.import_module(name)
