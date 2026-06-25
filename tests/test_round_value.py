from worker.round_label_builder import calculate_round_value


def test_round_value_rewards_new_findings_cves_and_critical():
    value = calculate_round_value(
        new_findings=2,
        new_cve=1,
        new_critical=1,
        risk_increase=True,
        confidence_increase=True,
    )

    assert value == 9


def test_round_value_no_change_is_zero():
    assert calculate_round_value(no_change=True) == 0


def test_round_value_penalizes_timeout_and_duplicate():
    assert calculate_round_value(tool_timeout=True, duplicate_finding=True) == -2
