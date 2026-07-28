"""Tests for MITRE ATT&CK tagging of findings."""

from modules.mitre.mapper import (
    CVE_MAP,
    MISCONFIG_MAP,
    PORT_MAP,
    SERVICE_MAP,
    TACTICS,
    ATTACKTag,
    MITREMapper,
)


class TestATTACKTag:
    def test_full_id_without_sub_technique(self):
        tag = ATTACKTag("T1190", "", "Initial Access", "TA0001", "Exploit")
        assert tag.full_id == "T1190"

    def test_full_id_with_sub_technique(self):
        tag = ATTACKTag("T1021", ".001", "Lateral Movement", "TA0008", "Remote Services")
        assert tag.full_id == "T1021.001"

    def test_mitigations_default_to_empty_list(self):
        assert ATTACKTag("T1190", "", "Initial Access", "TA0001", "Exploit").mitigations == []

    def test_explicit_mitigations_are_kept(self):
        tag = ATTACKTag("T1190", "", "Initial Access", "TA0001", "Exploit", mitigations=["M1050"])
        assert tag.mitigations == ["M1050"]

    def test_to_dict_uses_full_id(self):
        tag = ATTACKTag("T1021", ".004", "Lateral Movement", "TA0008", "Remote Services")
        assert tag.to_dict()["technique_id"] == "T1021.004"

    def test_to_dict_builds_attack_url(self):
        tag = ATTACKTag("T1190", "", "Initial Access", "TA0001", "Exploit")
        assert tag.to_dict()["url"] == "https://attack.mitre.org/techniques/T1190"

    def test_to_dict_contains_expected_keys(self):
        tag = ATTACKTag("T1190", "", "Initial Access", "TA0001", "Exploit", "desc")
        assert set(tag.to_dict()) == {
            "technique_id", "tactic", "tactic_id", "name", "description", "url",
        }


class TestFromCVE:
    def test_known_cve(self):
        tag = MITREMapper.from_cve("CVE-2021-44228")
        assert tag is not None
        assert tag.technique_id == "T1190"

    def test_lookup_is_case_insensitive(self):
        assert MITREMapper.from_cve("cve-2021-44228") is not None

    def test_unknown_cve_returns_none(self):
        assert MITREMapper.from_cve("CVE-1999-99999") is None

    def test_eternalblue_maps_to_lateral_movement(self):
        assert MITREMapper.from_cve("CVE-2017-0144").tactic == "Lateral Movement"

    def test_every_mapped_cve_has_a_valid_tactic(self):
        for cve_id, tag in CVE_MAP.items():
            assert tag.tactic in TACTICS, f"{cve_id} has unknown tactic {tag.tactic}"
            assert tag.tactic_id == TACTICS[tag.tactic], f"{cve_id} tactic_id mismatch"

    def test_every_mapped_cve_has_a_technique_id(self):
        for cve_id, tag in CVE_MAP.items():
            assert tag.technique_id.startswith("T"), f"{cve_id} bad technique id"


class TestFromService:
    def test_known_service(self):
        assert MITREMapper.from_service("ssh").technique_id == "T1021"

    def test_lookup_is_case_insensitive(self):
        assert MITREMapper.from_service("SSH") is not None

    def test_hyphenated_service_resolves_without_a_port(self):
        """Regression: keys containing hyphens must still match by name alone."""
        tag = MITREMapper.from_service("netbios-ssn")
        assert tag is not None
        assert tag.technique_id == "T1021"

    def test_hyphenated_service_resolves_with_a_port(self):
        assert MITREMapper.from_service("netbios-ssn", 139) is not None

    def test_port_fallback_when_service_is_unknown(self):
        assert MITREMapper.from_service("mystery", 3389).technique_id == "T1021"

    def test_port_fallback_when_service_is_blank(self):
        assert MITREMapper.from_service("", 6379) is not None

    def test_unknown_service_and_port_returns_none(self):
        assert MITREMapper.from_service("mystery", 65000) is None

    def test_unknown_service_without_port_returns_none(self):
        assert MITREMapper.from_service("mystery") is None

    def test_port_mapped_to_service_with_no_attack_entry_returns_none(self):
        # 110 -> "pop3", which has no SERVICE_MAP entry.
        assert MITREMapper.from_service("", 110) is None

    def test_every_port_map_target_is_a_string(self):
        for port, svc in PORT_MAP.items():
            assert isinstance(svc, str), f"port {port} maps to non-string"

    def test_every_service_map_entry_has_a_valid_tactic(self):
        for svc, tag in SERVICE_MAP.items():
            assert tag.tactic in TACTICS, f"{svc} has unknown tactic {tag.tactic}"


class TestFromMisconfig:
    def test_known_pattern(self):
        assert MITREMapper.from_misconfig("default_credentials").technique_id == "T1078"

    def test_lookup_is_case_insensitive(self):
        assert MITREMapper.from_misconfig("DEFAULT_CREDENTIALS") is not None

    def test_unknown_pattern_returns_none(self):
        assert MITREMapper.from_misconfig("not_a_pattern") is None

    def test_every_misconfig_entry_has_a_valid_tactic(self):
        for pattern, tag in MISCONFIG_MAP.items():
            assert tag.tactic in TACTICS, f"{pattern} has unknown tactic {tag.tactic}"


class TestTagFinding:
    def test_cve_produces_a_tag(self):
        tags = MITREMapper.tag_finding("Log4j", "vulnerable", cve_ids=["CVE-2021-44228"])
        assert any(t.technique_id == "T1190" for t in tags)

    def test_service_produces_a_tag(self):
        tags = MITREMapper.tag_finding("Open SSH", "port 22 open", service="ssh")
        assert any(t.technique_id == "T1021" for t in tags)

    def test_port_alone_produces_a_tag(self):
        tags = MITREMapper.tag_finding("Open RDP", "exposed", port=3389)
        assert any(t.technique_id == "T1021" for t in tags)

    def test_keyword_heuristic_matches_underscored_pattern(self):
        tags = MITREMapper.tag_finding("Weak password found", "the account uses a weak password")
        assert any(t.technique_id == "T1110" for t in tags)

    def test_keyword_heuristic_matches_literal_pattern(self):
        tags = MITREMapper.tag_finding("directory_listing enabled", "")
        assert any(t.technique_id == "T1083" for t in tags)

    def test_duplicate_techniques_are_deduplicated(self):
        tags = MITREMapper.tag_finding(
            "SMB", "vulnerable",
            cve_ids=["CVE-2017-0144", "CVE-2017-0145", "CVE-2017-0147"],
        )
        assert len({t.full_id for t in tags}) == len(tags)

    def test_unknown_cves_are_skipped(self):
        assert MITREMapper.tag_finding("x", "y", cve_ids=["CVE-1999-99999"]) == []

    def test_no_signals_produces_no_tags(self):
        assert MITREMapper.tag_finding("Nothing notable", "all clear") == []

    def test_combines_cve_and_service_signals(self):
        tags = MITREMapper.tag_finding(
            "SMB RCE", "EternalBlue", cve_ids=["CVE-2017-0144"], service="smb",
        )
        assert len(tags) >= 2

    def test_keyword_match_is_case_insensitive(self):
        tags = MITREMapper.tag_finding("ANONYMOUS ACCESS", "")
        assert any(t.technique_id == "T1078" for t in tags)

    def test_service_takes_precedence_over_port(self):
        """When both are given, the named service is looked up first."""
        tags = MITREMapper.tag_finding("x", "y", service="redis", port=3389)
        assert tags[0].description.startswith("Unauthenticated Redis")
