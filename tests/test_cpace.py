# ruff: noqa: E501  (official test vectors)
"""CPace against the test vectors of draft-irtf-cfrg-cpace-21, appendices A and B.1."""

import pytest

from lanpair import cpace

h = bytes.fromhex


def test_prepend_len_and_lv_cat():
    assert cpace.prepend_len(b"").hex() == "00"
    assert cpace.prepend_len(b"1234").hex() == "0431323334"
    assert cpace.prepend_len(bytes(range(127)))[:1].hex() == "7f"
    assert cpace.prepend_len(bytes(range(128)))[:2].hex() == "8001"
    assert cpace.lv_cat(b"1234", b"5", b"", b"678").hex() == "043132333401350003363738"
    assert (
        cpace.transcript_ir(b"123", b"PartyA", b"234", b"PartyB").hex()
        == "03313233065061727479410332333406506172747942"
    )


PRS = b"Password"
CI = h("0b415f696e69746961746f720b425f726573706f6e646572")
SID = h("7e4b4791d6a8ef019b936c79fb7f2c57")
YA_SCALAR = h("21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b319097153044080")
YB_SCALAR = h("848b0779ff415f0af4ea14df9dd1d3c29ac41d836c7808896c4eba19c51ac40a")


def test_generator():
    s = cpace.generator_string(PRS, CI, SID)
    assert len(s) == 170
    assert s.hex().startswith("0843506163653235350850617373776f72646d00")
    assert s.hex().endswith(
        "180b415f696e69746961746f720b425f726573706f6e646572107e4b4791d6a8ef019b936c79fb7f2c57"
    )
    assert (
        cpace.calculate_generator(PRS, CI, SID).hex()
        == "d04bf6d41f6a289632a2e929fa29bebd51092512a7829fdde7d314b62f05a73f"
    )


def test_full_exchange():
    g = cpace.calculate_generator(PRS, CI, SID)
    ya = cpace.scalar_mult(YA_SCALAR, g)
    yb = cpace.scalar_mult(YB_SCALAR, g)
    assert ya.hex() == "1d13c89278cdadd826f6d8d7f887701430f8380ddc17611cdd6dc989ce0c9f32"
    assert yb.hex() == "248cccf6d5cdc3646f0ad593f9e6cef4e69d4945f8372e623512ecea32185623"
    k = cpace.scalar_mult(YA_SCALAR, yb)
    assert k == cpace.scalar_mult(YB_SCALAR, ya)
    assert k.hex() == "5b067effbdc0b2a0e1d907b21ebb25cfedb96a852179a847c37e43ee71322c6b"
    t = cpace.transcript_ir(ya, b"ADa", yb, b"ADb")
    assert cpace.isk(SID, k, t).hex() == (
        "6e19b875f7a561d6b3ca3dbb9ef42ac55de3e717881018204b8922b4d5e53bb2"
        "aa82c300bea7b65d2b671da71922ddf6472301b79bc270adfa8bf413285f2263"
    )


S = h("af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff")
LOW_ORDER = {
    "0000000000000000000000000000000000000000000000000000000000000000": None,
    "0100000000000000000000000000000000000000000000000000000000000000": None,
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": None,
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800": None,
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157": None,
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": None,
    "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": "d8e2c776bbacd510d09fd9278b7edcd25fc5ae9adfba3b6e040e8d3b71b21806",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f": None,
    "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": "c85c655ebe8be44ba9c0ffde69f2fe10194458d137f09bbff725ce58803cdb38",
    "d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": "db64dafa9b8fdd136914e61461935fe92aa372cb056314e1231bc4ec12417456",
    "cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880": "e062dcd5376d58297be2618c7498f55baa07d7e03184e8aada20bca28888bf7a",
    "4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7": "993c6ad11c4c29da9a56f7691fd0ff8d732e49de6250b6c2e80003ff4629a175",
}


@pytest.mark.parametrize("u,q", LOW_ORDER.items())
def test_low_order_points(u, q):
    result = cpace.scalar_mult(S, h(u))
    if q is None:
        assert result == cpace.IDENTITY
        with pytest.raises(cpace.CPaceError):
            cpace.isk(SID, result, b"")
    else:
        assert result.hex() == q
