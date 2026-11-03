import pytest

from pii_toolkit.policy import PolicyError, load_policy, parse_policy

BASE = {"version": 1, "name": "p", "columns": {"email": "hash"}}


def test_example_policy_is_valid():
    policy = load_policy("examples/policy.yaml")
    assert policy.rule_for("card_number").options["keep_last"] == 4
    assert policy.rule_for("notes").rule == "nullify"


def test_all_errors_are_reported_together():
    with pytest.raises(PolicyError) as exc:
        parse_policy(
            {
                "version": 9,
                "columns": {
                    "a": {"rule": "scramble"},
                    "b": {"rule": "mask", "keep_last": 99},
                    "c": {"rule": "hash", "salt": "x"},
                },
            }
        )
    joined = "\n".join(exc.value.errors)
    assert "version" in joined
    assert "name is required" in joined
    assert "unknown rule 'scramble'" in joined
    assert "keep_last" in joined
    assert "option 'salt' is not valid" in joined
    assert len(exc.value.errors) == 5


@pytest.mark.parametrize(
    "patch, fragment",
    [
        ({"columns": {}}, "columns is required"),
        ({"extra": 1}, "unknown top-level key"),
        ({"secrets": {"hash_salt": "inline-secret"}}, "not allowed"),
        ({"secrets": {"hash_salt_env": "not a var"}}, "must name an environment variable"),
        ({"columns": {"x": {"rule": "mask", "mask_char": "##"}}}, "mask_char"),
        ({"columns": {"x": {"rule": "tokenise", "vault": "yes"}}}, "vault must be"),
        ({"columns": {"x": 42}}, "expected a rule name"),
    ],
)
def test_specific_validation_errors(patch, fragment):
    with pytest.raises(PolicyError, match=fragment):
        parse_policy({**BASE, **patch})


def test_non_mapping_policy_rejected():
    with pytest.raises(PolicyError):
        parse_policy(["not", "a", "mapping"])


def test_policy_hash_ignores_key_order_but_not_content():
    a = parse_policy({"version": 1, "name": "p", "columns": {"x": "hash", "y": "nullify"}})
    b = parse_policy({"columns": {"y": "nullify", "x": "hash"}, "name": "p", "version": 1})
    c = parse_policy({"version": 1, "name": "p", "columns": {"x": "hash", "y": "hash"}})
    assert a.policy_hash == b.policy_hash
    assert a.policy_hash != c.policy_hash
