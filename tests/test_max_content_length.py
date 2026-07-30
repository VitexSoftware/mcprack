def test_oversized_request_body_is_rejected(client):
    limit = client.application.config["MAX_CONTENT_LENGTH"]
    oversized_password = "x" * (limit + 1024)

    resp = client.post(
        "/login", data={"username": "nobody", "password": oversized_password}
    )
    assert resp.status_code == 413
