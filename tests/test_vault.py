import pytest

from pii_toolkit.engine import apply_policy
from pii_toolkit.vault import REIDENTIFY_ROLE, TokenVault


def test_vault_reidentifies_for_authorised_role_only(
    spark, customers, secrets, key_manager, policy, tmp_path
):
    vault = TokenVault(spark, str(tmp_path / "vault"), key_manager)
    protected = apply_policy(customers, policy, secrets, key_manager=key_manager, vault=vault).df

    with pytest.raises(PermissionError):
        vault.reidentify(protected, "email", role="analyst")

    back = vault.reidentify(protected.select("customer_id", "email"), "email", REIDENTIFY_ROLE)
    expected = {r.customer_id: r.email for r in customers.collect()}
    assert {r.customer_id: r.email for r in back.collect()} == expected


def test_vault_is_insert_only_and_stores_no_plaintext(
    spark, customers, secrets, key_manager, policy, tmp_path
):
    vault = TokenVault(spark, str(tmp_path / "vault"), key_manager)
    apply_policy(customers, policy, secrets, key_manager=key_manager, vault=vault)
    first = vault.read().count()
    apply_policy(customers, policy, secrets, key_manager=key_manager, vault=vault)
    assert vault.read().count() == first == customers.select("email").distinct().count()

    emails = {r.email for r in customers.collect()}
    for row in vault.read().collect():
        assert not any(e in row.value_ct for e in emails)


def test_missing_vault_is_an_error(customers, secrets, key_manager, policy):
    with pytest.raises(ValueError, match="TokenVault"):
        apply_policy(customers, policy, secrets, key_manager=key_manager)
