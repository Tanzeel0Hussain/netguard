import pytest

from netguard.models import normalize_mac


@pytest.mark.parametrize(
    "raw",
    ["AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "aabbccddeeff", "  aa:bb:cc:dd:ee:ff\n"],
)
def test_normalize_mac_accepts_common_formats(raw):
    assert normalize_mac(raw) == "aa:bb:cc:dd:ee:ff"


@pytest.mark.parametrize("raw", ["", "aa:bb:cc:dd:ee", "aa:bb-cc:dd:ee:ff", "zz:bb:cc:dd:ee:ff"])
def test_normalize_mac_rejects_garbage(raw):
    with pytest.raises(ValueError):
        normalize_mac(raw)
