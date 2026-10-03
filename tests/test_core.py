from rawarontek.core import ScanContext, command_available


def test_context_set():
    ctx = ScanContext("example.com", {})
    ctx.set("status", 200)
    assert ctx.summary["status"] == 200


def test_python_command_exists():
    assert command_available("python") or command_available("python3")
