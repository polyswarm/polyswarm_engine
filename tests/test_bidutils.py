from polyswarm_engine import rescale_to_bid


def test_rescale_to_bid():
    bounty = {"rules": {"min_allowed_bid": 100, "max_allowed_bid": 200}}
    assert 125 == rescale_to_bid(
        bounty,
        25,
        min=0,
        max=100,
    )
