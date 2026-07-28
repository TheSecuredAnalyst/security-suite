"""Tests for the OpenAPI/Swagger specification parser."""

import json

import pytest

from modules.apisec.openapi_parser import (
    APIEndpoint,
    APIParameter,
    OpenAPIParser,
    ParsedAPI,
)

V3_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Demo API", "version": "2.1.0", "description": "A demo"},
    "servers": [{"url": "https://api.example.com/v1"}, {"url": "https://staging.example.com"}],
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
            "apiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
        }
    },
    "paths": {
        "/users": {
            "get": {
                "operationId": "listUsers",
                "summary": "List users",
                "tags": ["users"],
                "parameters": [
                    {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                ],
                "responses": {"200": {"description": "ok"}},
            },
            "post": {
                "operationId": "createUser",
                "requestBody": {"content": {"application/json": {}}},
                "security": [{"bearerAuth": []}],
                "responses": {"201": {"description": "created"}},
            },
        },
        "/users/{id}": {
            "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
            ],
            "get": {"operationId": "getUser", "responses": {"200": {"description": "ok"}}},
            "delete": {"operationId": "deleteUser", "responses": {"204": {"description": "gone"}}},
        },
    },
}

V2_SPEC = {
    "swagger": "2.0",
    "info": {"title": "Legacy API", "version": "1.0.0"},
    "host": "legacy.example.com",
    "basePath": "/api",
    "schemes": ["https", "http"],
    "securityDefinitions": {
        "apiKey": {"type": "apiKey", "in": "query", "name": "key"},
    },
    "paths": {
        "/items": {
            "get": {
                "operationId": "listItems",
                "parameters": [{"name": "page", "in": "query", "type": "integer"}],
                "responses": {"200": {"description": "ok"}},
            },
        },
    },
}


@pytest.fixture
def parser():
    return OpenAPIParser()


class TestParseV3:
    def test_info_fields(self, parser):
        api = parser.parse_string(json.dumps(V3_SPEC))
        assert api.title == "Demo API"
        assert api.version == "2.1.0"
        assert api.description == "A demo"

    def test_servers_are_collected(self, parser):
        api = parser.parse_string(json.dumps(V3_SPEC))
        assert api.servers == ["https://api.example.com/v1", "https://staging.example.com"]

    def test_base_url_is_the_first_server(self, parser):
        assert parser.parse_string(json.dumps(V3_SPEC)).base_url == "https://api.example.com/v1"

    def test_all_operations_become_endpoints(self, parser):
        api = parser.parse_string(json.dumps(V3_SPEC))
        assert len(api.endpoints) == 4

    def test_methods_are_uppercased(self, parser):
        api = parser.parse_string(json.dumps(V3_SPEC))
        assert {e.method for e in api.endpoints} == {"GET", "POST", "DELETE"}

    def test_operation_metadata_is_captured(self, parser):
        api = parser.parse_string(json.dumps(V3_SPEC))
        ep = next(e for e in api.endpoints if e.operation_id == "listUsers")
        assert ep.summary == "List users"
        assert ep.tags == ["users"]
        assert ep.responses == {"200": {"description": "ok"}}

    def test_request_body_is_captured(self, parser):
        api = parser.parse_string(json.dumps(V3_SPEC))
        ep = next(e for e in api.endpoints if e.operation_id == "createUser")
        assert ep.request_body is not None

    def test_endpoints_without_a_body_have_none(self, parser):
        api = parser.parse_string(json.dumps(V3_SPEC))
        ep = next(e for e in api.endpoints if e.operation_id == "listUsers")
        assert ep.request_body is None

    def test_operation_security_is_captured(self, parser):
        api = parser.parse_string(json.dumps(V3_SPEC))
        ep = next(e for e in api.endpoints if e.operation_id == "createUser")
        assert ep.security == [{"bearerAuth": []}]

    def test_endpoint_with_no_security_is_flagged_as_empty(self, parser):
        """Endpoints with no security requirement are the BOLA/auth-bypass candidates."""
        api = parser.parse_string(json.dumps(V3_SPEC))
        unauth = [e for e in api.endpoints if not e.security]
        assert len(unauth) == 3

    def test_parameter_type_read_from_schema(self, parser):
        api = parser.parse_string(json.dumps(V3_SPEC))
        ep = next(e for e in api.endpoints if e.operation_id == "listUsers")
        assert ep.parameters[0].name == "limit"
        assert ep.parameters[0].param_type == "integer"

    def test_path_level_parameters_are_inherited_by_operations(self, parser):
        api = parser.parse_string(json.dumps(V3_SPEC))
        ep = next(e for e in api.endpoints if e.operation_id == "getUser")
        assert [p.name for p in ep.parameters] == ["id"]
        assert ep.parameters[0].location == "path"
        assert ep.parameters[0].required is True

    def test_path_parameters_are_shared_across_sibling_operations(self, parser):
        api = parser.parse_string(json.dumps(V3_SPEC))
        delete = next(e for e in api.endpoints if e.operation_id == "deleteUser")
        assert [p.name for p in delete.parameters] == ["id"]


class TestParseSecuritySchemes:
    def test_v3_http_bearer(self, parser):
        api = parser.parse_string(json.dumps(V3_SPEC))
        scheme = api.security_schemes["bearerAuth"]
        assert scheme.scheme_type == "http"
        assert scheme.scheme == "bearer"
        assert scheme.bearer_format == "JWT"

    def test_v3_api_key(self, parser):
        api = parser.parse_string(json.dumps(V3_SPEC))
        scheme = api.security_schemes["apiKeyAuth"]
        assert scheme.scheme_type == "apiKey"
        assert scheme.location == "header"

    def test_v2_security_definitions(self, parser):
        api = parser.parse_string(json.dumps(V2_SPEC))
        assert api.security_schemes["apiKey"].location == "query"

    def test_missing_type_defaults_to_apikey(self, parser):
        spec = {"openapi": "3.0.0", "components": {"securitySchemes": {"x": {}}}, "paths": {}}
        api = parser.parse_string(json.dumps(spec))
        assert api.security_schemes["x"].scheme_type == "apiKey"

    def test_no_security_schemes_yields_empty_dict(self, parser):
        api = parser.parse_string(json.dumps({"openapi": "3.0.0", "paths": {}}))
        assert api.security_schemes == {}

    def test_oauth2_flows_are_preserved(self, parser):
        flows = {"implicit": {"authorizationUrl": "https://x/auth", "scopes": {}}}
        spec = {
            "openapi": "3.0.0",
            "components": {"securitySchemes": {"o": {"type": "oauth2", "flows": flows}}},
            "paths": {},
        }
        api = parser.parse_string(json.dumps(spec))
        assert api.security_schemes["o"].flows == flows


class TestParseV2:
    def test_base_url_built_from_scheme_host_and_basepath(self, parser):
        api = parser.parse_string(json.dumps(V2_SPEC))
        assert api.base_url == "https://legacy.example.com/api"

    def test_first_scheme_wins(self, parser):
        spec = dict(V2_SPEC, schemes=["http", "https"])
        assert parser.parse_string(json.dumps(spec)).base_url.startswith("http://")

    def test_defaults_when_host_and_basepath_are_absent(self, parser):
        spec = {"swagger": "2.0", "paths": {}}
        assert parser.parse_string(json.dumps(spec)).base_url == "https://localhost/"

    def test_v2_parameter_type_read_from_top_level_type(self, parser):
        api = parser.parse_string(json.dumps(V2_SPEC))
        assert api.endpoints[0].parameters[0].param_type == "integer"

    def test_v2_request_body_is_not_parsed(self, parser):
        """requestBody is an OpenAPI 3 construct; it must be ignored for 2.0."""
        spec = {
            "swagger": "2.0",
            "paths": {"/x": {"post": {"requestBody": {"content": {}}, "responses": {}}}},
        }
        assert parser.parse_string(json.dumps(spec)).endpoints[0].request_body is None

    def test_spec_without_a_version_key_is_treated_as_v2(self, parser):
        spec = {"info": {"title": "No Version"}, "host": "x.example.com", "paths": {}}
        assert parser.parse_string(json.dumps(spec)).base_url == "https://x.example.com/"


class TestParseEdgeCases:
    def test_empty_spec_uses_defaults(self, parser):
        api = parser.parse_string("{}")
        assert api.title == "Unknown API"
        assert api.version == "1.0.0"
        assert api.endpoints == []

    def test_no_paths_yields_no_endpoints(self, parser):
        assert parser.parse_string(json.dumps({"openapi": "3.0.0"})).endpoints == []

    def test_non_http_keys_in_a_path_item_are_ignored(self, parser):
        spec = {
            "openapi": "3.0.0",
            "paths": {"/x": {"get": {"responses": {}}, "summary": "ignored", "servers": []}},
        }
        assert len(parser.parse_string(json.dumps(spec)).endpoints) == 1

    def test_all_seven_http_methods_are_recognised(self, parser):
        methods = ["get", "post", "put", "patch", "delete", "head", "options"]
        spec = {"openapi": "3.0.0", "paths": {"/x": {m: {"responses": {}} for m in methods}}}
        assert len(parser.parse_string(json.dumps(spec)).endpoints) == 7

    def test_ref_parameters_are_skipped(self, parser):
        spec = {
            "openapi": "3.0.0",
            "paths": {"/x": {"get": {"parameters": [{"$ref": "#/components/parameters/Id"}]}}},
        }
        assert parser.parse_string(json.dumps(spec)).endpoints[0].parameters == []

    def test_parameter_defaults_when_fields_are_missing(self, parser):
        spec = {"openapi": "3.0.0", "paths": {"/x": {"get": {"parameters": [{}]}}}}
        param = parser.parse_string(json.dumps(spec)).endpoints[0].parameters[0]
        assert param.name == ""
        assert param.location == "query"
        assert param.required is False
        assert param.param_type == "string"

    def test_v3_servers_absent_leaves_base_url_empty(self, parser):
        api = parser.parse_string(json.dumps({"openapi": "3.0.0", "paths": {}}))
        assert api.base_url == ""
        assert api.servers == []

    def test_numeric_version_does_not_crash(self, parser):
        """YAML parses an unquoted `openapi: 3.0` as a float, not a string."""
        spec = {"openapi": 3.0, "servers": [{"url": "https://x"}], "paths": {}}
        assert parser.parse_string(json.dumps(spec)).base_url == "https://x"

    def test_numeric_swagger_version_does_not_crash(self, parser):
        spec = {"swagger": 2.0, "host": "x.example.com", "paths": {}}
        assert parser.parse_string(json.dumps(spec)).base_url == "https://x.example.com/"


class TestParseString:
    def test_json_is_the_default_format(self, parser):
        assert parser.parse_string(json.dumps(V3_SPEC)).title == "Demo API"

    def test_yaml_format(self, parser):
        yaml_spec = """
openapi: "3.0.0"
info:
  title: YAML API
  version: "1.2.3"
paths:
  /ping:
    get:
      operationId: ping
"""
        api = parser.parse_string(yaml_spec, format="yaml")
        assert api.title == "YAML API"
        assert api.endpoints[0].operation_id == "ping"

    def test_invalid_json_raises(self, parser):
        with pytest.raises(json.JSONDecodeError):
            parser.parse_string("{not json")


class TestParseFile:
    def test_json_file(self, parser, tmp_path):
        f = tmp_path / "spec.json"
        f.write_text(json.dumps(V3_SPEC))
        assert parser.parse_file(str(f)).title == "Demo API"

    def test_yaml_file_by_extension(self, parser, tmp_path):
        f = tmp_path / "spec.yaml"
        f.write_text('openapi: "3.0.0"\ninfo:\n  title: From YAML\npaths: {}\n')
        assert parser.parse_file(str(f)).title == "From YAML"

    def test_yml_extension_is_also_yaml(self, parser, tmp_path):
        f = tmp_path / "spec.yml"
        f.write_text('openapi: "3.0.0"\ninfo:\n  title: Short Ext\npaths: {}\n')
        assert parser.parse_file(str(f)).title == "Short Ext"

    def test_missing_file_raises(self, parser, tmp_path):
        with pytest.raises(FileNotFoundError):
            parser.parse_file(str(tmp_path / "nope.json"))


class TestParseURL:
    async def test_fetches_and_parses_json(self, parser, monkeypatch):
        _install_fake_client(monkeypatch, json.dumps(V3_SPEC), "application/json")
        api = await parser.parse_url("https://api.example.com/openapi.json")
        assert api.title == "Demo API"

    async def test_yaml_detected_from_content_type(self, parser, monkeypatch):
        _install_fake_client(
            monkeypatch, 'openapi: "3.0.0"\ninfo:\n  title: CT YAML\npaths: {}\n',
            "application/yaml",
        )
        api = await parser.parse_url("https://api.example.com/spec")
        assert api.title == "CT YAML"

    async def test_yaml_detected_from_url_suffix(self, parser, monkeypatch):
        _install_fake_client(
            monkeypatch, 'openapi: "3.0.0"\ninfo:\n  title: Suffix YAML\npaths: {}\n',
            "text/plain",
        )
        api = await parser.parse_url("https://api.example.com/spec.yaml")
        assert api.title == "Suffix YAML"

    async def test_http_error_propagates(self, parser, monkeypatch):
        import httpx
        _install_fake_client(monkeypatch, "", "application/json", raise_for_status=True)
        with pytest.raises(httpx.HTTPStatusError):
            await parser.parse_url("https://api.example.com/openapi.json")


def _install_fake_client(monkeypatch, text, content_type, raise_for_status=False):
    """Replace httpx.AsyncClient with a stub returning a canned response."""
    import httpx

    class FakeResponse:
        def __init__(self):
            self.text = text
            self.headers = {"content-type": content_type}

        def raise_for_status(self):
            if raise_for_status:
                raise httpx.HTTPStatusError(
                    "404", request=httpx.Request("GET", "https://x"),
                    response=httpx.Response(404),
                )

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, url):
            return FakeResponse()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)


class TestDiscoverSpecURL:
    def test_returns_common_locations(self, parser):
        urls = parser.discover_spec_url("https://api.example.com")
        assert "https://api.example.com/openapi.json" in urls
        assert "https://api.example.com/swagger.json" in urls

    def test_trailing_slash_is_normalised(self, parser):
        urls = parser.discover_spec_url("https://api.example.com/")
        assert "https://api.example.com//openapi.json" not in urls
        assert "https://api.example.com/openapi.json" in urls

    def test_all_candidates_are_absolute_urls(self, parser):
        for url in parser.discover_spec_url("https://api.example.com"):
            assert url.startswith("https://api.example.com/")

    def test_candidate_list_has_no_duplicates(self, parser):
        urls = parser.discover_spec_url("https://api.example.com")
        assert len(urls) == len(set(urls))

    def test_includes_framework_specific_paths(self, parser):
        urls = parser.discover_spec_url("https://api.example.com")
        assert any("api-docs" in u for u in urls)
        assert any(".well-known" in u for u in urls)


class TestDataclasses:
    def test_endpoint_defaults(self):
        ep = APIEndpoint(path="/x", method="GET")
        assert ep.parameters == []
        assert ep.responses == {}
        assert ep.security == []
        assert ep.tags == []
        assert ep.request_body is None

    def test_parameter_defaults(self):
        p = APIParameter(name="q", location="query")
        assert p.required is False
        assert p.param_type == "string"
        assert p.example is None

    def test_parsed_api_description_defaults_to_empty(self):
        api = ParsedAPI(
            title="t", version="1", base_url="", endpoints=[],
            security_schemes={}, servers=[],
        )
        assert api.description == ""
