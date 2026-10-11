import json

import pytest

from scamlens.cli import main

SCAM = "Selamat Anda menang! Install aplikasi di http://jne-cek.xyz/foto.apk lalu kirim OTP"
AMAN = "Besok rapat jam 10 di kantor ya, jangan lupa bawa laptop."


def test_check_scam_kode_keluar_1(capsys):
    assert main(["check", SCAM, "--no-color"]) == 1
    out = capsys.readouterr().out
    assert "[BAHAYA]" in out and "OTP-01" in out


def test_check_aman_kode_keluar_0(capsys):
    assert main(["check", AMAN]) == 0
    assert "[AMAN?]" in capsys.readouterr().out


def test_json_juga_memakai_kode_keluar(capsys):
    assert main(["check", SCAM, "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["level"] == "tinggi" and data["findings"]


def test_fail_on_never_dan_tinggi(capsys):
    assert main(["check", SCAM, "--fail-on", "never"]) == 0
    assert main(["check", "Akun Anda diblokir, segera hubungi admin WhatsApp", "--fail-on", "tinggi"]) == 0


def test_quiet_hanya_satu_baris(capsys):
    main(["check", SCAM, "-q"])
    assert len(capsys.readouterr().out.strip().splitlines()) == 1


def test_file_tidak_ada_kode_2(capsys):
    assert main(["check", "--file", "/tidak/ada.txt"]) == 2
    assert "tidak ditemukan" in capsys.readouterr().err


def test_teks_kosong_kode_2(capsys):
    assert main(["check", "   "]) == 2


def test_stdin(monkeypatch, capsys):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(SCAM))
    assert main(["check"]) == 1


def test_batch_txt_dan_jsonl(tmp_path, capsys):
    f = tmp_path / "pesan.txt"
    f.write_text(f"{AMAN}\n\n{SCAM}\n", encoding="utf-8")
    assert main(["batch", str(f), "--no-color"]) == 1
    assert "Total 2" in capsys.readouterr().out
    j = tmp_path / "pesan.jsonl"
    j.write_text(json.dumps({"text": AMAN}) + "\n", encoding="utf-8")
    assert main(["batch", str(j), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["level"] == "rendah"


def test_rules_menampilkan_aturan_teks_dan_url(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "OTP-01" in out and "URL-09" in out


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "scamlens" in capsys.readouterr().out
