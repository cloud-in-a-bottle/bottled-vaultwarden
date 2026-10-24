from openhost_test_harness import OpenhostStack


def test_app_serves_owner(stack: OpenhostStack) -> None:
    response = stack.owner_session.get(f"{stack.url}/", timeout=30)
    assert response.status_code < 400, f"GET / returned {response.status_code}: {response.text[:500]}"
