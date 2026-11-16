import pytest

from toy.http import Browser, FakeNetwork, Request, Response


def echo(name):
    def app(request):
        return Response(200, {}, {"app": name, "path": request.path}, {})

    return app


def two_sites():
    network = FakeNetwork()
    network.mount("https://id.example", echo("provider"))
    network.mount("https://app.example", echo("client"))
    return network


def test_request_exposes_path_and_query():
    request = Request("GET", "https://id.example/authorize?client_id=app&state=x%20y")
    assert request.path == "/authorize"
    assert request.query == {"client_id": "app", "state": "x y"}
    assert Request("POST", "https://id.example/token").form == {}


def test_send_routes_by_origin():
    network = two_sites()
    assert network.send(Request("GET", "https://id.example/jwks")).body["app"] == "provider"
    assert network.send(Request("GET", "https://app.example/cb")).body["app"] == "client"
    assert network.send(Request("GET", "https://app.example/cb")).body["path"] == "/cb"


def test_send_to_an_unknown_origin_raises_lookup_error():
    network = two_sites()
    with pytest.raises(LookupError):
        network.send(Request("GET", "https://evil.example/"))
    with pytest.raises(LookupError):
        network.send(Request("GET", "http://id.example/"))


def test_browser_follows_a_302_and_stores_cookies_per_origin():
    network = FakeNetwork()
    callback = {"Location": "https://app.example/cb?code=c1"}
    network.mount("https://id.example", lambda request: Response(302, callback, "", {"sid": "p1"}))
    network.mount("https://app.example", echo("client"))
    browser = Browser(network)
    landed = browser.get("https://id.example/authorize")
    assert landed.status == 200
    assert landed.body["path"] == "/cb"
    assert browser.cookies("https://id.example") == {"sid": "p1"}
    assert browser.cookies("https://app.example") == {}
    assert [request.url for request in browser.history] == [
        "https://id.example/authorize",
        "https://app.example/cb?code=c1",
    ]


def setting_cookie(name):
    def app(request):
        return Response(200, {}, request.cookies, {name: "c1"})

    return app


def test_browser_sends_each_origin_only_its_own_cookies():
    network = FakeNetwork()
    for origin, cookie in (("https://id.example", "sid"), ("https://app.example", "rp")):
        network.mount(origin, setting_cookie(cookie))
    browser = Browser(network)
    browser.get("https://id.example/")
    browser.get("https://app.example/")
    assert browser.get("https://id.example/").body == {"sid": "c1"}
    assert browser.get("https://app.example/").body == {"rp": "c1"}


def test_browser_post_sends_the_form_and_a_none_cookie_deletes():
    def signs_in_then_out(request):
        sid = "p1" if request.method == "GET" else None
        return Response(200, {}, request.form, {"sid": sid})

    network = FakeNetwork()
    network.mount("https://id.example", signs_in_then_out)
    browser = Browser(network)
    browser.get("https://id.example/")
    assert browser.cookies("https://id.example") == {"sid": "p1"}
    assert browser.post("https://id.example/logout", {"x": "1"}).body == {"x": "1"}
    assert browser.cookies("https://id.example") == {}


def hops_then_ok(hops):
    def app(request):
        step = int(request.path.strip("/") or 0)
        if step < hops:
            return Response(302, {"Location": f"/{step + 1}"}, "", {})
        return Response(200, {}, "ok", {})

    return app


def test_browser_follows_ten_relative_redirects_but_not_eleven():
    network = FakeNetwork()
    network.mount("https://id.example", hops_then_ok(10))
    network.mount("https://app.example", hops_then_ok(11))
    browser = Browser(network)
    assert browser.get("https://id.example/").body == "ok"
    assert browser.history[-1].url == "https://id.example/10"
    with pytest.raises(RuntimeError, match="redirects"):
        browser.get("https://app.example/")
