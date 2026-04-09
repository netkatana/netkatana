from netkatana.rules import http_rules


def test_http_report_only_rules_match_enforced_rule_severity():
    rules_by_code = {rule.code: rule for rule in http_rules}
    report_only_codes = [code for code in rules_by_code if "_report_only_" in code]

    assert report_only_codes

    for report_only_code in report_only_codes:
        enforced_code = report_only_code.replace("_report_only", "")
        assert enforced_code in rules_by_code
        assert rules_by_code[report_only_code].severity == rules_by_code[enforced_code].severity
