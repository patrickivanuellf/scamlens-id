from pathlib import Path

from scamlens.cli import main
from scamlens.evaluate import Metrics, evaluate, load_dataset

DATA = Path(__file__).resolve().parent.parent / "data" / "eval"


def test_metrik_dihitung_benar():
    m = Metrics(tp=8, fp=2, fn=2, tn=8)
    assert m.precision == 0.8 and m.recall == 0.8 and m.accuracy == 0.8
    assert abs(m.f1 - 0.8) < 1e-9
    assert Metrics().precision == 0.0  # tanpa pembagi nol


def test_dataset_valid_dan_seimbang():
    samples = load_dataset(DATA / "pesan_uji.csv")
    assert len(samples) > 200
    assert {s.label for s in samples} == {"scam", "ham"}
    assert {s.split for s in samples} == {"dev", "test"}


def test_regresi_kualitas_pada_dataset_pengembangan():
    """Pagar pengaman: setiap perubahan aturan tidak boleh menurunkan kualitas jauh."""
    for name in ("pesan_uji.csv",):
        report = evaluate(load_dataset(DATA / name), "sedang")
        assert report.metrics.precision >= 0.95
        assert report.metrics.recall >= 0.90


def test_set_buta_tidak_runtuh():
    """Set buta dibekukan: angka jujur (recall ~73%). Batas longgar agar hanya regresi besar yang gagal."""
    report = evaluate(load_dataset(DATA / "pesan_buta.csv"), "sedang")
    assert report.metrics.precision >= 0.95
    assert report.metrics.recall >= 0.65


def test_cli_eval_dan_ambang(capsys):
    path = str(DATA / "pesan_uji.csv")
    assert main(["eval", path, "--split", "test"]) == 0
    assert "Precision" in capsys.readouterr().out
    assert main(["eval", path, "--min-recall", "1.01"]) == 1
    assert main(["eval", "/tidak/ada.csv"]) == 2
