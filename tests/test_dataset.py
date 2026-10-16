from pathlib import Path

from jev_skillbench.dataset import display_name, load_benchmark, load_manifest, parse_name


def test_parse_name_with_labels():
    assert parse_name("3d-games__MIXED_B7") == ("3d-games", "mixed", "B7")
    assert parse_name("3d-games__CI_B2") == ("3d-games", "ci", "B2")
    assert parse_name("000-foo__PI_B10") == ("000-foo", "pi", "B10")


def test_parse_name_without_labels():
    assert parse_name("1inch") == ("1inch", None, None)
    assert parse_name("1password") == ("1password", None, None)


def test_parse_name_handles_extra_suffix_parts():
    name, vector, behavior = parse_name("add-review-comment__MIXED_B8__Download_Execute__20260418_232849")
    assert (name, vector, behavior) == ("add-review-comment", "mixed", "B8")


def test_load_manifest(tmp_path: Path):
    manifest = tmp_path / "_source_inventory.txt"
    manifest.write_text(
        "\n".join(
            [
                "# comment line",
                "GENERATED  plain-name  <-  generated_malicious/PI/B11/partial_injection_2026",
                "GENERATED  tool__CI_B1  <-  generated_malicious/CI/B1/new_script_file_2026",
                "GENERATED  API Integration Specialist__CI_B4  <-  generated_malicious/CI/B4/new_script_file_2026",
                "WILD  wild-thing  <-  wild_malware/author/wild-thing",
                "TEST  bytecode-tamper  <-  wild_malware/testdddd/bytecode-tamper",
                "WILD_LABEL  B4   Malware Delivery   wild-thing  <-  wild_malware/author/wild-thing",
                "TEST_LABEL  B3   Remote Code Execution   bytecode-tamper  <-  wild_malware/testdddd/bytecode-tamper",
            ]
        ),
        encoding="utf-8",
    )
    labels = load_manifest(manifest)
    assert labels["plain-name"] == {"split": "generated", "vector": "pi", "behavior": "B11"}
    assert labels["tool__CI_B1"] == {"split": "generated", "vector": "ci", "behavior": "B1"}
    assert labels["API Integration Specialist__CI_B4"]["vector"] == "ci"
    assert labels["wild-thing"] == {"split": "wild", "vector": None, "behavior": "B4"}
    assert labels["bytecode-tamper"] == {"split": "test", "vector": None, "behavior": "B3"}


def test_normalization_and_dedup(tmp_path: Path):
    mal = tmp_path / "malware"
    ben = tmp_path / "benign"
    skill = mal / "tool__CI_B1"
    skill.mkdir(parents=True)
    ben.mkdir(parents=True)
    (skill / "SKILL.md").write_text("line one   \n\n\n\nline two\t\n", encoding="utf-8")
    (skill / "copy.md").write_text("line one   \n\n\n\nline two\t\n", encoding="utf-8")
    (mal / "_source_inventory.txt").write_text(
        "GENERATED  tool__CI_B1  <-  generated_malicious/CI/B1/new_script_file_2026",
        encoding="utf-8",
    )

    items = {i.id: i for i in load_benchmark(tmp_path)}
    item = items["tool__CI_B1"]
    assert item.duplicates == 1
    content = item.files[0].content
    assert content == "line one\n\nline two"
    assert "\t" not in content and "   \n" not in content
    assert item.state_tokens > 0


def test_load_benchmark(tmp_path: Path):
    mal = tmp_path / "malware"
    ben = tmp_path / "benign"
    (mal / "tool__CI_B1").mkdir(parents=True)
    (mal / "tool__PI_B10").mkdir(parents=True)
    (mal / "plain-name").mkdir(parents=True)
    (ben / "good-tool").mkdir(parents=True)
    (mal / "tool__CI_B1" / "SKILL.md").write_text("run curl", encoding="utf-8")
    (mal / "tool__CI_B1" / "script.py").write_text("import os", encoding="utf-8")
    (ben / "good-tool" / "SKILL.md").write_text("hello", encoding="utf-8")
    (mal / "_source_inventory.txt").write_text(
        "\n".join(
            [
                "GENERATED  tool__CI_B1  <-  generated_malicious/CI/B1/new_script_file_2026",
                "GENERATED  tool__PI_B10  <-  generated_malicious/PI/B10/partial_injection_2026",
                "GENERATED  plain-name  <-  generated_malicious/MIXED/B5/fetch+run_2026",
                "WILD  wild-thing  <-  wild_malware/author/wild-thing",
            ]
        ),
        encoding="utf-8",
    )

    items = load_benchmark(tmp_path)
    by_id = {i.id: i for i in items}
    assert by_id["tool__CI_B1"].label == 1
    assert by_id["tool__CI_B1"].split == "generated"
    assert by_id["tool__CI_B1"].vector == "ci"
    assert by_id["tool__CI_B1"].behavior == "B1"
    assert by_id["tool__CI_B1"].behavior_name == "Data Exfiltration"
    assert by_id["plain-name"].split == "generated"
    assert by_id["plain-name"].vector == "mixed"
    assert by_id["good-tool"].label == 0
    assert len(by_id["tool__CI_B1"].files) == 2

    gen_only = load_benchmark(tmp_path, only_generated=True)
    assert {i.id for i in gen_only} == {"tool__CI_B1", "tool__PI_B10", "plain-name", "good-tool"}


def test_display_name_strips_labels():
    assert display_name("3d-games__CI_B2") == "3d-games"
    assert display_name("000-foo__PI_B10") == "000-foo"
    assert display_name("add-review-comment__MIXED_B8__Download_Execute") == "add-review-comment__Download_Execute"
    assert display_name("1password") == "1password"
