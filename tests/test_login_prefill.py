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
