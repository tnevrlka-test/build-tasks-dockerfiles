import datetime
import json
import sys
import uuid
from pathlib import Path

import pytest
import sbom_for_modelcar_task

TEST_DATA: Path = Path(__file__).parent / "test_data"


@pytest.mark.parametrize("sbom_type", ["cyclonedx", "spdx"])
def test_main(sbom_type: str, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    # Mock out external factors for SPDX (randomness, date and time)
    monkeypatch.setattr(uuid, "uuid4", lambda: "a29a127a-daf6-44d3-a840-4eca194e9b41")
    monkeypatch.setattr(
        sbom_for_modelcar_task,
        "_datetime_utc_now",
        lambda: datetime.datetime(2025, 1, 14, 11, 46, 34, tzinfo=datetime.UTC),
    )

    MODELCAR_IMAGE = "repository.example.com/aipcc/modelcar-image:v1.0@sha256:8ef392004884ee00ccaabd279ea6859fc021c7b613f3103f568277f078764998"
    BASE_IMAGE = "repository.example.com/aipcc/base-image:v2.3@sha256:3a7bd3e2360a5d5f1a4e4b8a4c6e0d3f2a4b2c8a5f1e6d7b8a9c0d1e2f3a4b5"
    MODEL_IMAGE = "repository.example.com/aipcc/model-image:v1.1@sha256:9f1e2d3c4b5a6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "__unused_script_name__",
            "--modelcar-image",
            MODELCAR_IMAGE,
            "--base-image",
            BASE_IMAGE,
            "--model-image",
            MODEL_IMAGE,
            "--sbom-type",
            sbom_type,
        ],
    )
    sbom_for_modelcar_task.main()
    out, _ = capsys.readouterr()

    got_sbom = json.loads(out)
    expect_sbom = json.loads(TEST_DATA.joinpath(f"{sbom_type}.json").read_text())
    assert got_sbom == expect_sbom
