from storai.safety import DeviceIdentity, verify_device_safety


def test_device_safety_blocks_protected_parent(monkeypatch) -> None:
    parent = DeviceIdentity(
        path="/dev/sda",
        name="sda",
        size=1000,
        model="Disk",
        serial="ABC",
        devtype="disk",
        mountpoints=["/"],
        fstype=None,
        pkname=None,
    )
    part = DeviceIdentity(
        path="/dev/sda1",
        name="sda1",
        size=500,
        model="Disk",
        serial="ABC1",
        devtype="part",
        mountpoints=[],
        fstype=None,
        pkname="sda",
    )

    monkeypatch.setattr("storai.safety.device_inventory", lambda: {"/dev/sda": parent, "/dev/sda1": part})
    monkeypatch.setattr("storai.safety.command_exists", lambda _: False)

    report = verify_device_safety("/dev/sda1")
    assert not report.ok
    assert any("protected" in reason for reason in report.reasons)
