import logging
import typing as t

from polyswarm_engine.constants import NCT_TO_WEI_CONVERSION


if t.TYPE_CHECKING:
    from .typing import Bid, Bounty

log = logging.getLogger(__name__)


def bid_median(bounty: 'Bounty') -> 'Bid':
    """Get the median of the minimum and maximum allowed bid from :param:`bounty`"""
    min_bid, max_bid = bid_range(bounty)
    return (min_bid+max_bid) // 2


def bid_min(bounty: 'Bounty') -> 'Bid':
    """Get the minimum allowed bid from :param:`bounty`"""
    return bid_range(bounty)[0]


def bid_max(bounty: 'Bounty') -> 'Bid':
    """Get the maximum allowed bid from :param:`bounty`"""
    return bid_range(bounty)[1]


def bid_range(bounty: 'Bounty') -> t.Tuple['Bid', 'Bid']:
    """Return a tuple of the minimum & maximum allowed bit from :param:`bounty`"""
    rules = bounty['rules']
    return rules['min_allowed_bid'], rules['max_allowed_bid']


def rescale_to_bid(bounty: 'Bounty', value: 't.SupportsInt', min=0, max=100) -> 'Bid':
    """Scale a `value` (a number between ``min`` and ``max``) to ``bounty``'s maximum bid"""
    min_bid, max_bid = bid_range(bounty)

    if value >= min and value <= max:
        return int(normalize(value, min, max, min_bid, max_bid))
    else:
        log.error("value (%f) is not between %f and %f", value, min, max)
        return min_bid


def dni_to_bid(bounty: 'Bounty', value: str) -> 'Bid':
    """Transform string value from the None / Low / Med / High scale to a bid

    From: https://www.dni.gov/files/documents/ICD/ICD_203_TA_Analytic_Standards_21_Dec_2022.pdf

    | DNI Scale                               | Polyswarm Bid |
    |-----------------------------------------+---------------|
    | Not Specified                           | Not Specified |
    | Almost No Chance / Remote               |             5 |
    | Very Unlikely / Highly Improbable       |            15 |
    | Unlikely / Improbable                   |            30 |
    | Roughly Even Chance / Roughly Even Odds |            50 |
    | Likely / Probable                       |            70 |
    | Very Likely / Highly Probable           |            85 |
    | Almost Certain / Nearly Certain         |            95 |to appropriate bid amounts.
    """
    value = value.lower()

    if value == "none":
        return bid_min(bounty)
    elif value == "low":
        return rescale_to_bid(bounty, 25, max=100)
    elif value == "med":
        return rescale_to_bid(bounty, 75, max=100)
    elif value == "high":
        return bid_max(bounty)
    else:
        raise ValueError(bounty, value)


def normalize(x, x_min, x_max, a, b):
    """Scale `x`, a value between `x_min` and `x_max`, to a value between `a` and `b`"""
    return a + (((x-x_min) * (b-a)) / (x_max-x_min))


def to_wei(nct):
    """Convert a value in NCT to wei, usable in the bid value"""
    return nct * NCT_TO_WEI_CONVERSION
