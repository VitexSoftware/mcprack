def test_query_param_prefill_ignored_outside_demo_mode(client):
    client.application.config["DEMO_MODE"] = False
    resp = client.get("/login?username=someone&password=secretpw")
    body = resp.data.decode()
    assert 'value="someone"' not in body
    assert 'value="secretpw"' not in body


def test_query_param_prefill_honored_in_demo_mode(client):
    client.application.config["DEMO_MODE"] = True
    resp = client.get("/login?username=someone&password=secretpw")
    body = resp.data.decode()
    assert 'value="someone"' in body
    assert 'value="secretpw"' in body


def test_demo_mode_prefills_defaults_without_query_params(client):
    client.application.config["DEMO_MODE"] = True
    client.application.config["DEMO_USERNAME"] = "demo"
    client.application.config["DEMO_PASSWORD"] = "demo"
    resp = client.get("/login")
    body = resp.data.decode()
    assert 'value="demo"' in body


def test_demo_mode_defaults_not_shown_outside_demo_mode(client):
    client.application.config["DEMO_MODE"] = False
    client.application.config["DEMO_USERNAME"] = "demo"
    client.application.config["DEMO_PASSWORD"] = "demo"
    resp = client.get("/login")
    body = resp.data.decode()
    assert 'value="demo"' not in body
