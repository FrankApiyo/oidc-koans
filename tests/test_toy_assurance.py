import pytest

from toy.assurance import amr_includes, check_level
from toy.errors import InvalidToken
from toy.provider import ACR_MFA, ACR_PASSWORD

ID, OTHER = "https://id.example", "https://other-id.example"
POLICY = {
    ID: {"mfa": frozenset({ACR_MFA}), "any": frozenset({ACR_PASSWORD, ACR_MFA})},
    OTHER: {"any": frozenset({ACR_PASSWORD, ACR_MFA})},
}


@pytest.mark.parametrize("amr", [["otp"], ["pwd", "otp", "mfa"], ["otp", "pwd"]])
def test_amr_includes_a_listed_method_in_any_order(amr):
    assert amr_includes({"amr": amr}, "otp") is True


@pytest.mark.parametrize("amr", [
    None, [], ["pwd"], ["pwd", "mfa"], ["OTP"], ["hotp"], "otp", "pwd otp", ("otp",),
    ["pwd", ["otp"]], ["otp", 1], {"otp": True},
])
def test_amr_includes_nothing_but_a_listed_string(amr):
    assert amr_includes({"amr": amr}, "otp") is False
    assert amr_includes({}, "otp") is False


@pytest.mark.parametrize("claims, level", [
    ({"iss": ID, "acr": ACR_MFA}, "mfa"),
    ({"iss": ID, "acr": ACR_PASSWORD}, "any"),
    ({"iss": OTHER, "acr": ACR_MFA}, "any"),
])
def test_check_level_accepts_an_agreed_value(claims, level):
    assert check_level(claims, POLICY, level) is None


@pytest.mark.parametrize("claims, level", [
    ({"iss": ID}, "mfa"),
    ({"iss": ID, "acr": ACR_PASSWORD}, "mfa"),
    ({"iss": ID, "acr": "0"}, "mfa"),
    ({"iss": ID, "acr": ""}, "any"),
    ({"iss": ID, "acr": None}, "any"),
    ({"iss": ID, "acr": True}, "mfa"),
    ({"iss": ID, "acr": 2}, "mfa"),
    ({"iss": ID, "acr": ACR_MFA.upper()}, "mfa"),
    ({"iss": ID, "acr": [ACR_MFA]}, "mfa"),
    ({"iss": ID, "acr": "urn:toy:acr:hwk"}, "mfa"),
    ({"iss": ID, "acr": ACR_MFA}, "hwk"),
    ({"iss": OTHER, "acr": ACR_MFA}, "mfa"),
    ({"iss": "https://mallory.example", "acr": ACR_MFA}, "any"),
    ({"acr": ACR_MFA}, "mfa"),
    ({"iss": [ID], "acr": ACR_MFA}, "mfa"),
])
def test_check_level_refuses_anything_not_agreed(claims, level):
    with pytest.raises(InvalidToken) as refused:
        check_level(claims, POLICY, level)
    assert refused.value.reason == "acr_not_met"
