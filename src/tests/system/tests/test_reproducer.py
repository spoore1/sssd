"""
Identity Tests

These tests cover all the searches, queries, and lookups performed by SSSD.

:requirement: Identity
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericADProvider, GenericProvider
from sssd_test_framework.roles.ipa import IPA
from sssd_test_framework.roles.ldap import LDAP
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.topology(KnownTopology.IPA)
def test_reproducer__test0_lookup_users(client: Client, ipa: IPA):
    """
    :title: Resolve user by name with "id"
    :setup:
        1. Create the following users 'user1', 'user2' and 'user3' specifying the UIDs
        2. Configure SSSD with "ldap_id_mapping = false" and start SSSD
    :steps:
        1. Lookup 'user1', 'user2' and 'user3' using the UID
        2. Check the results
    :expectedresults:
        1. Users are found
        2. Results have the correct name and UIDs
    :customerscenario: False
    """
    ids = [("user1", 10001), ("user2", 10002), ("user3", 10003)]
    for user, id in ids:
        ipa.user(user).add(uid=id, gid=id + 500)

    client.sssd.start()

    for name, uid in ids:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id!"
        assert result.user.name == name, f"Username {result.user.name} is incorrect, {name} expected!"
        assert result.user.id == uid, f"User id {result.user.id} is incorrect, {uid} expected!"


@pytest.mark.topology(KnownTopology.IPA)
def test_reproducer__test1_lookup_users_again(client: Client, ipa: IPA):
    """
    :title: Resolve user by name with "id"
    :setup:
        1. Create the following users 'user1', 'user2' and 'user3' specifying the UIDs
        2. Configure SSSD with "ldap_id_mapping = false" and start SSSD
    :steps:
        1. Lookup 'user1', 'user2' and 'user3' using the UID
        2. Check the results
    :expectedresults:
        1. Users are found
        2. Results have the correct name and UIDs
    :customerscenario: False
    """
    ids = [("user1", 10001), ("user2", 10002), ("user3", 10003)]
    for user, id in ids:
        ipa.user(user).add(uid=id, gid=id + 500)

    client.sssd.start()

    for name, uid in ids:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id!"
        assert result.user.name == name, f"Username {result.user.name} is incorrect, {name} expected!"
        assert result.user.id == uid, f"User id {result.user.id} is incorrect, {uid} expected!"


@pytest.mark.topology(KnownTopology.IPA)
def test_reproducer__test2_lookup_users_again(client: Client, ipa: IPA):
    """
    :title: Resolve user by name with "id"
    :setup:
        1. Create the following users 'user1', 'user2' and 'user3' specifying the UIDs
        2. Configure SSSD with "ldap_id_mapping = false" and start SSSD
    :steps:
        1. Lookup 'user1', 'user2' and 'user3' using the UID
        2. Check the results
    :expectedresults:
        1. Users are found
        2. Results have the correct name and UIDs
    :customerscenario: False
    """
    ids = [("user1", 10001), ("user2", 10002), ("user3", 10003)]
    for user, id in ids:
        ipa.user(user).add(uid=id, gid=id + 500)

    client.sssd.start()

    for name, uid in ids:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id!"
        assert result.user.name == name, f"Username {result.user.name} is incorrect, {name} expected!"
        assert result.user.id == uid, f"User id {result.user.id} is incorrect, {uid} expected!"


@pytest.mark.topology(KnownTopology.IPA)
def test_reproducer__test3_lookup_users_again(client: Client, ipa: IPA):
    """
    :title: Resolve user by name with "id"
    :setup:
        1. Create the following users 'user1', 'user2' and 'user3' specifying the UIDs
        2. Configure SSSD with "ldap_id_mapping = false" and start SSSD
    :steps:
        1. Lookup 'user1', 'user2' and 'user3' using the UID
        2. Check the results
    :expectedresults:
        1. Users are found
        2. Results have the correct name and UIDs
    :customerscenario: False
    """
    ids = [("user1", 10001), ("user2", 10002), ("user3", 10003)]
    for user, id in ids:
        ipa.user(user).add(uid=id, gid=id + 500)

    client.sssd.start()

    for name, uid in ids:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id!"
        assert result.user.name == name, f"Username {result.user.name} is incorrect, {name} expected!"
        assert result.user.id == uid, f"User id {result.user.id} is incorrect, {uid} expected!"


@pytest.mark.topology(KnownTopology.IPA)
def test_reproducer__test4_lookup_users_again(client: Client, ipa: IPA):
    """
    :title: Resolve user by name with "id"
    :setup:
        1. Create the following users 'user1', 'user2' and 'user3' specifying the UIDs
        2. Configure SSSD with "ldap_id_mapping = false" and start SSSD
    :steps:
        1. Lookup 'user1', 'user2' and 'user3' using the UID
        2. Check the results
    :expectedresults:
        1. Users are found
        2. Results have the correct name and UIDs
    :customerscenario: False
    """
    ids = [("user1", 10001), ("user2", 10002), ("user3", 10003)]
    for user, id in ids:
        ipa.user(user).add(uid=id, gid=id + 500)

    client.sssd.start()

    for name, uid in ids:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id!"
        assert result.user.name == name, f"Username {result.user.name} is incorrect, {name} expected!"
        assert result.user.id == uid, f"User id {result.user.id} is incorrect, {uid} expected!"


@pytest.mark.topology(KnownTopology.IPA)
def test_reproducer__test5_lookup_users_again(client: Client, ipa: IPA):
    """
    :title: Resolve user by name with "id"
    :setup:
        1. Create the following users 'user1', 'user2' and 'user3' specifying the UIDs
        2. Configure SSSD with "ldap_id_mapping = false" and start SSSD
    :steps:
        1. Lookup 'user1', 'user2' and 'user3' using the UID
        2. Check the results
    :expectedresults:
        1. Users are found
        2. Results have the correct name and UIDs
    :customerscenario: False
    """
    ids = [("user1", 10001), ("user2", 10002), ("user3", 10003)]
    for user, id in ids:
        ipa.user(user).add(uid=id, gid=id + 500)

    client.sssd.start()

    for name, uid in ids:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id!"
        assert result.user.name == name, f"Username {result.user.name} is incorrect, {name} expected!"
        assert result.user.id == uid, f"User id {result.user.id} is incorrect, {uid} expected!"


@pytest.mark.topology(KnownTopology.IPA)
def test_reproducer__test6_lookup_users_again(client: Client, ipa: IPA):
    """
    :title: Resolve user by name with "id"
    :setup:
        1. Create the following users 'user1', 'user2' and 'user3' specifying the UIDs
        2. Configure SSSD with "ldap_id_mapping = false" and start SSSD
    :steps:
        1. Lookup 'user1', 'user2' and 'user3' using the UID
        2. Check the results
    :expectedresults:
        1. Users are found
        2. Results have the correct name and UIDs
    :customerscenario: False
    """
    ids = [("user1", 10001), ("user2", 10002), ("user3", 10003)]
    for user, id in ids:
        ipa.user(user).add(uid=id, gid=id + 500)

    client.sssd.start()

    for name, uid in ids:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id!"
        assert result.user.name == name, f"Username {result.user.name} is incorrect, {name} expected!"
        assert result.user.id == uid, f"User id {result.user.id} is incorrect, {uid} expected!"


@pytest.mark.topology(KnownTopology.IPA)
def test_reproducer__test7_lookup_users_again(client: Client, ipa: IPA):
    """
    :title: Resolve user by name with "id"
    :setup:
        1. Create the following users 'user1', 'user2' and 'user3' specifying the UIDs
        2. Configure SSSD with "ldap_id_mapping = false" and start SSSD
    :steps:
        1. Lookup 'user1', 'user2' and 'user3' using the UID
        2. Check the results
    :expectedresults:
        1. Users are found
        2. Results have the correct name and UIDs
    :customerscenario: False
    """
    ids = [("user1", 10001), ("user2", 10002), ("user3", 10003)]
    for user, id in ids:
        ipa.user(user).add(uid=id, gid=id + 500)

    client.sssd.start()

    for name, uid in ids:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id!"
        assert result.user.name == name, f"Username {result.user.name} is incorrect, {name} expected!"
        assert result.user.id == uid, f"User id {result.user.id} is incorrect, {uid} expected!"


@pytest.mark.topology(KnownTopology.IPA)
def test_reproducer__test8_lookup_users_again(client: Client, ipa: IPA):
    """
    :title: Resolve user by name with "id"
    :setup:
        1. Create the following users 'user1', 'user2' and 'user3' specifying the UIDs
        2. Configure SSSD with "ldap_id_mapping = false" and start SSSD
    :steps:
        1. Lookup 'user1', 'user2' and 'user3' using the UID
        2. Check the results
    :expectedresults:
        1. Users are found
        2. Results have the correct name and UIDs
    :customerscenario: False
    """
    ids = [("user1", 10001), ("user2", 10002), ("user3", 10003)]
    for user, id in ids:
        ipa.user(user).add(uid=id, gid=id + 500)

    client.sssd.start()

    for name, uid in ids:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id!"
        assert result.user.name == name, f"Username {result.user.name} is incorrect, {name} expected!"
        assert result.user.id == uid, f"User id {result.user.id} is incorrect, {uid} expected!"


@pytest.mark.topology(KnownTopology.IPA)
def test_reproducer__test9_lookup_users_again(client: Client, ipa: IPA):
    """
    :title: Resolve user by name with "id"
    :setup:
        1. Create the following users 'user1', 'user2' and 'user3' specifying the UIDs
        2. Configure SSSD with "ldap_id_mapping = false" and start SSSD
    :steps:
        1. Lookup 'user1', 'user2' and 'user3' using the UID
        2. Check the results
    :expectedresults:
        1. Users are found
        2. Results have the correct name and UIDs
    :customerscenario: False
    """
    ids = [("user1", 10001), ("user2", 10002), ("user3", 10003)]
    for user, id in ids:
        ipa.user(user).add(uid=id, gid=id + 500)

    client.sssd.start()

    for name, uid in ids:
        result = client.tools.id(name)
        assert result is not None, f"User {name} was not found using id!"
        assert result.user.name == name, f"Username {result.user.name} is incorrect, {name} expected!"
        assert result.user.id == uid, f"User id {result.user.id} is incorrect, {uid} expected!"


