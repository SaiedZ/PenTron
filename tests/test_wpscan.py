from pentron.tools import base, registry
from pentron.tools.pipeline import run_selected_tools
from pentron.tools.wpscan import run_wpscan, wordpress_detected


def test_wordpress_detection_uses_prior_recon_evidence():
    assert wordpress_detected({"whatweb": "WordPress[6.8]"})
    assert wordpress_detected({"curl_headers": "Link: </wp-json/>"})
    assert not wordpress_detected({"whatweb": "Apache, PHP", "nmap": "80/tcp"})


def test_wpscan_is_skipped_without_wordpress(monkeypatch):
    called = False

    def fake_run(*args, **kwargs):
        nonlocal called
        called = True
        return "unexpected"

    monkeypatch.setattr(base, "run_tool", fake_run)
    output = run_wpscan("example.com")

    assert "SKIPPED" in output
    assert called is False


def test_wpscan_command_is_fixed_to_vulnerable_plugins_and_themes(monkeypatch):
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured.update(kwargs)
        return "ok"

    monkeypatch.setattr(base, "run_tool", fake_run)
    assert run_wpscan("example.com", wordpress_is_detected=True) == "ok"

    command = captured["command"]
    assert command[command.index("--enumerate") + 1] == "vp,vt"
    assert command[command.index("--plugins-detection") + 1] == "passive"
    assert command[command.index("--themes-detection") + 1] == "passive"
    assert not {"u", "--usernames", "--passwords", "--password-attack"} & set(command)
    assert captured["timeout"] == 300


def test_selected_wpscan_runs_after_detection_even_if_requested_first(monkeypatch):
    whatweb = registry.find_by_name("whatweb")
    wpscan = registry.find_by_name("wpscan")
    assert whatweb and wpscan

    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return "WordPress website" if command[0] == "whatweb" else "safe"

    monkeypatch.setattr(base, "run_tool", fake_run)

    results = run_selected_tools("example.com", [wpscan.key, whatweb.key])

    assert results == {"whatweb": "WordPress website", "wpscan": "safe"}
    assert [command[0] for command in commands] == ["whatweb", "wpscan"]


def test_selected_wpscan_stays_skipped_without_detection(monkeypatch):
    whatweb = registry.find_by_name("whatweb")
    wpscan = registry.find_by_name("wpscan")
    assert whatweb and wpscan

    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        return "Apache website"

    monkeypatch.setattr(base, "run_tool", fake_run)
    results = run_selected_tools("example.com", [whatweb.key, wpscan.key])

    assert "SKIPPED" in results["wpscan"]
    assert [command[0] for command in commands] == ["whatweb"]


def test_wpscan_cannot_be_dispatched_by_the_ai():
    assert "wpscan" not in registry.allowed_commands()
