from purest.docs.apidoc import get_apidoc
from purest.docs.openapi import generate_full_openapi_spec
from purest import api_endp, configure


def _sample_module():
    class mod:
        ENDP_PATH = "/sample"
        LOGIN_REQUIRED = True
        DOCSTRING = {"GET": "Sample get", "POST": "Sample post"}
        REQUIRED_FIELDS = {"POST": ["name"]}
        OPTIONAL_FIELDS = {"GET": ["q"]}
        RESULT_EXAMPLE = {"GET": "{'ok': true}"}

        @staticmethod
        @api_endp
        def impl_GET(headers, query=None):
            return {"ok": True}

        @staticmethod
        @api_endp
        def impl_POST(headers, data):
            return {"ok": True}

    return mod


def test_apidoc_html_and_plain():
    modules = [_sample_module()]
    html = get_apidoc(modules, format="html")
    plain = get_apidoc(modules, format="plain")
    assert "<html" in html.lower()
    assert "/sample" in html
    assert "Sample get" in html
    assert "GET: /sample" in plain
    assert "Required: name" in plain
    assert "Login required: True" in plain


def test_openapi_spec_shape():
    configure(openapi_title="Demo API", openapi_version="2.3.4")
    spec = generate_full_openapi_spec([_sample_module()])
    assert spec["openapi"] == "3.0.0"
    assert spec["info"]["title"] == "Demo API"
    assert spec["info"]["version"] == "2.3.4"
    assert "/sample" in spec["paths"]
    assert "get" in spec["paths"]["/sample"]
    assert "post" in spec["paths"]["/sample"]
    assert spec["paths"]["/sample"]["get"]["security"] == [
        {"AuthUserCookie": [], "AuthTokenCookie": []}
    ]
    schemes = spec["components"]["securitySchemes"]
    assert "AuthUserCookie" in schemes
    assert "AuthTokenCookie" in schemes
    assert schemes["AuthUserCookie"]["in"] == "cookie"
    assert schemes["AuthTokenCookie"]["in"] == "cookie"
