"""Tests for modules.codescan (secrets, dependency and pattern checks)."""

import json

import httpx
import pytest

from modules.codescan import CodeScanner, deps, sast, secrets
from modules.codescan.walker import is_test_path, iter_files


# Credential-shaped values are assembled at runtime so this file never contains
# a string that secret scanners (including GitHub push protection) would flag.
def fake(prefix: str, body: str) -> str:
    return prefix + body


# ── secrets ────────────────────────────────────────────────────────────────
class TestSecrets:
    def test_finds_aws_key_and_redacts_it(self):
        key = fake("AKIA", "Q7RT2MZP4K9WX3VB")
        found = secrets.scan_text(f'const k = "{key}";\n', "src/app.js")
        assert [f.rule_id for f in found] == ["secret.aws-access-key"]
        assert key not in found[0].snippet and key not in found[0].message
        assert found[0].data["redacted"] == "AKIA…(20 chars)"
        assert found[0].line == 1

    def test_private_key_header(self):
        text = "x\n" + fake("-----BEGIN RSA ", "PRIVATE KEY-----") + "\nMIIE...\n"
        found = secrets.scan_text(text, "deploy/key.pem")
        assert found[0].rule_id == "secret.private-key" and found[0].line == 2

    def test_generic_secret_needs_entropy_and_digits(self):
        real = 'apiKey: "' + fake("q8Zr2", "Lx7Vw0Pk3Nf5") + '"'
        word = 'password: "passwordConfirmation"'
        assert len(secrets.scan_text(real, "a.js")) == 1
        assert secrets.scan_text(word, "a.js") == []

    @pytest.mark.parametrize("value", ["your-api-key-here-123", "process.env.API_KEY_1234",
                                       "${API_TOKEN_123456}", "changeme1234567890"])
    def test_placeholders_ignored(self, value):
        assert secrets.scan_text(f'token = "{value}"', "a.js") == []

    def test_test_code_is_downgraded(self):
        key = fake("AKIA", "Q7RT2MZP4K9WX3VB")
        found = secrets.scan_text(f'"{key}"', "tests/fixture.js")
        assert found[0].severity == "low" and found[0].data["in_tests"]


# ── pattern checks ─────────────────────────────────────────────────────────
def rules(code: str, rel: str = "src/ui.js", lang: str = "js") -> list[str]:
    return [f.rule_id for f in sast.scan_text(code, rel, lang)]


class TestHtmlSinks:
    def test_unescaped_template_value_is_reported(self):
        found = sast.scan_text("el.innerHTML = `<b>${ticket.subject}</b>`;", "src/ui.js", "js")
        assert found[0].rule_id == "js.html-sink.innerhtml"
        assert found[0].data["unescaped"] == ["ticket.subject"]
        assert found[0].confidence == "medium"

    @pytest.mark.parametrize("code", [
        "el.innerHTML = `<b>${escapeHtml(ticket.subject)}</b>`;",
        "el.innerHTML = `<b>${esc(t.name)}</b><i>${items.length}</i>`;",
        "el.innerHTML = '<p>static</p>';",
        "el.innerHTML = '';",
        "el.innerHTML = `<p class=\"${open ? 'on' : 'off'}\">${n + 1}</p>`;",
        "el.innerHTML = `${rows.map((r) => `<li>${esc(r.name)}</li>`).join('')}`;",
        "el.innerHTML = renderCard(item);",
        "el.innerHTML = `<p>${icons.trash}${formatDate(d)}</p>`;",
        "if (a.innerHTML === b) {}",
    ])
    def test_safe_writes_are_not_reported(self, code):
        assert rules(code) == []

    def test_nested_template_reports_the_inner_raw_value(self):
        code = "list.innerHTML = items.map((i) => `<li>${i.title}</li>`).join('');"
        found = sast.scan_text(code, "src/ui.js", "js")
        assert found[0].data["unescaped"] == ["i.title"]

    def test_template_passed_to_a_helper_is_not_descended(self):
        assert rules("art.innerHTML = qrSvg(url, { title: `QR for ${c.name}` });") == []

    def test_multiline_template(self):
        code = "el.innerHTML = `\n  <div>\n    ${msg.body}\n  </div>`;\nnext();"
        assert rules(code) == ["js.html-sink.innerhtml"]

    def test_url_attribute_needs_scheme_check(self):
        code = 'a.innerHTML = `<a href="${esc(link.url)}">x</a>`;'
        assert rules(code) == ["js.html-sink.url-scheme"]
        assert rules('a.innerHTML = `<a href="${safeUrl(link.url)}">x</a>`;') == []

    def test_insert_adjacent_html(self):
        assert rules("el.insertAdjacentHTML('beforeend', `<p>${c.text}</p>`);") == \
            ["js.html-sink.insertadjacent"]


class TestOtherJsRules:
    def test_eval_call_but_not_method_definitions_or_comments(self):
        assert rules("const r = eval(src);") == ["js.eval"]
        assert rules("class C { eval(t: number): Vec3 { return v; } }", "a.ts") == []
        assert rules(" *   a curve { kind, eval(v) } on 0..1") == []
        assert rules("const y = c.eval(t);") == []

    def test_message_handler_without_origin_check(self):
        bad = "window.addEventListener('message', (e) => { run(e.data); });"
        good = "window.addEventListener('message', (e) => { if (e.origin !== ORIGIN) return; run(e.data); });"
        assert rules(bad) == ["js.message-no-origin-check"]
        assert rules(good) == []

    def test_named_message_handler_is_followed_to_its_definition(self):
        code = ("const onMessage = (e) => { if (e.source !== frame) return; go(e.data); };\n"
                "window.addEventListener('message', onMessage);")
        assert rules(code) == []

    def test_weak_random_token(self):
        assert rules("const token = Math.random().toString(36).slice(2);") == ["js.weak-random"]
        assert rules("const jitter = Math.random() * 10;") == []

    def test_cors_wildcard_escalates_with_credentials(self):
        code = ("h.set('Access-Control-Allow-Origin', '*');\n"
                "h.set('Access-Control-Allow-Credentials', 'true');")
        found = sast.scan_text(code, "worker/index.js", "js")
        assert found[0].rule_id == "js.cors-wildcard" and found[0].severity == "high"

    def test_minified_files_are_skipped(self):
        assert sast.scan_text("x=1;" * 200 + "eval(a)", "app.js", "js") == []


class TestPhpRules:
    def test_raw_sql_with_variable(self):
        assert rules('DB::select("SELECT * FROM t WHERE id = $id");', "app/X.php", "php") == \
            ["php.raw-sql-interpolation"]
        assert rules("->whereRaw('id = ?', [$id])", "app/X.php", "php") == []

    def test_blade_unescaped_output(self):
        assert rules("<p>{!! $post->body !!}</p>", "resources/views/p.blade.php", "php") == \
            ["php.blade-unescaped"]
        assert rules("{!! csrf_field() !!}", "v.blade.php", "php") == []


# ── walker ─────────────────────────────────────────────────────────────────
class TestWalker:
    @pytest.mark.parametrize("rel,expected", [
        ("tests/a.js", True), ("src/a.test.ts", True), ("e2e/x.spec.js", True),
        ("dev/puter-mock.js", True), ("tools/build.mjs", True), ("src/ui/app.js", False),
    ])
    def test_is_test_path(self, rel, expected):
        assert is_test_path(rel) is expected

    def test_skips_node_modules_and_tests(self, tmp_path):
        (tmp_path / "node_modules" / "x").mkdir(parents=True)
        (tmp_path / "node_modules" / "x" / "i.js").write_text("eval(a)")
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "t.js").write_text("eval(a)")
        (tmp_path / "app.js").write_text("eval(a)")
        names = [p.name for p, _ in iter_files(tmp_path, skip_tests=True)]
        assert names == ["app.js"]


# ── dependencies ───────────────────────────────────────────────────────────
LOCK = {
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "app"},
        "node_modules/pdfjs-dist": {"version": "5.7.284"},
        "node_modules/vitest": {"version": "2.1.9", "dev": True},
        "node_modules/@scope/pkg": {"version": "1.0.0"},
        "packages/local": {"version": "0.0.1"},
    },
}


class TestDeps:
    def test_parse_package_lock_v3(self):
        pkgs = deps.parse_package_lock(LOCK, "app/package-lock.json")
        assert {(p.name, p.version, p.dev) for p in pkgs} == {
            ("pdfjs-dist", "5.7.284", False), ("vitest", "2.1.9", True), ("@scope/pkg", "1.0.0", False)}

    def test_parse_composer_and_requirements(self):
        comp = deps.parse_composer_lock({"packages": [{"name": "laravel/framework", "version": "v11.0.1"}],
                                         "packages-dev": [{"name": "phpunit/phpunit", "version": "10.0"}]},
                                        "composer.lock")
        assert [(p.name, p.version, p.dev) for p in comp] == [
            ("laravel/framework", "11.0.1", False), ("phpunit/phpunit", "10.0", True)]
        req = deps.parse_requirements("requests==2.31.0\n# c\nflask>=2\nuvicorn[standard]==0.30.1\n",
                                      "requirements.txt")
        assert [(p.name, p.version) for p in req] == [("requests", "2.31.0"), ("uvicorn", "0.30.1")]

    def test_scan_with_mocked_osv(self, tmp_path):
        (tmp_path / "package-lock.json").write_text(json.dumps(LOCK))

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/querybatch"):
                qs = json.loads(request.content)["queries"]
                return httpx.Response(200, json={"results": [
                    {"vulns": [{"id": "GHSA-test-pdfj"}]} if q["package"]["name"] == "pdfjs-dist"
                    else {"vulns": [{"id": "GHSA-test-vite"}]} if q["package"]["name"] == "vitest"
                    else {} for q in qs]})
            vid = request.url.path.rsplit("/", 1)[-1]
            return httpx.Response(200, json={
                "id": vid, "summary": "Bad thing", "aliases": ["CVE-2026-0001"],
                "database_specific": {"severity": "HIGH"},
                "affected": [{"package": {"ecosystem": "npm", "name": "pdfjs-dist"},
                              "ranges": [{"events": [{"introduced": "0"}, {"fixed": "6.2.108"}]}]}]})

        client = httpx.Client(transport=httpx.MockTransport(handler))
        found, stats = deps.scan(tmp_path, client)
        by = {f.data["package"]: f for f in found}
        assert by["pdfjs-dist"].severity == "high" and by["pdfjs-dist"].data["fixed"] == ["6.2.108"]
        assert by["pdfjs-dist"].data["cve"] == "CVE-2026-0001"
        assert by["vitest"].severity == "medium" and "not shipped" in by["vitest"].message
        assert stats["packages"] == 3 and stats["vulnerable_packages"] == 2


# ── scanner / output ───────────────────────────────────────────────────────
class TestScanner:
    def test_offline_scan_and_sarif(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "ui.js").write_text("el.innerHTML = `<b>${msg.body}</b>`;\n")
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "t.js").write_text("eval(x)\n")
        sc = CodeScanner(tmp_path, offline=True)
        found = sc.run()
        assert [f.location for f in found] == ["src/ui.js:1"]
        assert sc.stats["deps"] == {"skipped": "offline"}

        sarif = sc.to_sarif(found)
        run = sarif["runs"][0]
        assert run["results"][0]["ruleId"] == "js.html-sink.innerhtml"
        assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
        assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "5.5"

        result = sc.to_scan_result(found)
        assert result.findings[0].data["check"] == "sast"

    def test_include_tests(self, tmp_path):
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "t.js").write_text("eval(x)\n")
        assert CodeScanner(tmp_path, offline=True, include_tests=True).run()[0].severity == "low"
