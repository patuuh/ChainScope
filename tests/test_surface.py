"""Validation for the permissionless-surface estimator (core/cs_surface.py).

The signal is only trustworthy if it reproduces ground truth we established
independently, so these tests pin the two data points that motivated the module:

  * GMX `router/ExchangeRouter.sol` -- counted manually at 22 unguarded mutating
    externals (the ADL audit described them as "permissionless-by-design user entry
    points"). Must score 22.
  * GMX `fee/FeeDistributor.sol` -- 781 lines, 2 audit mentions, and ZERO
    permissionless attack surface; every state-mover is keeper/timelock gated. A
    deep-dive there returned nothing. Must score 0.

A third regression guard: `onlyFeeDistributionKeeper` is not in any hand-written
guard list, so the detector must be pattern-based.
"""

from __future__ import annotations

import os

import pytest

from core.cs_surface import analyze_file

GMX = "/home/charad7/Developments/Personal/Hacks/Immunefi/GMX/repos/gmx-synthetics/contracts"

pytestmark = pytest.mark.skipif(
    not os.path.isdir(GMX), reason="gmx-synthetics clone not present"
)


def _perm(rel: str) -> list:
    return [h for h in analyze_file(os.path.join(GMX, rel)) if h.permissionless]


def test_exchange_router_matches_manual_count() -> None:
    """22 unguarded mutating externals, counted by hand in an earlier pass."""
    assert len(_perm("router/ExchangeRouter.sol")) == 22


def test_fee_distributor_has_no_permissionless_surface() -> None:
    """The dead end that motivated building this module in the first place."""
    assert _perm("fee/FeeDistributor.sol") == []


def test_unlisted_role_modifier_is_detected() -> None:
    """`onlyFeeDistributionKeeper` is not in the word list; the pattern must catch it."""
    hits = {h.name: h for h in analyze_file(os.path.join(GMX, "fee/FeeDistributor.sol"))}
    assert "depositReferralRewards" in hits
    assert not hits["depositReferralRewards"].permissionless, (
        "onlyFeeDistributionKeeper must be recognised as a role guard"
    )


def test_external_handler_is_permissive() -> None:
    """Confirmed by the dedicated residue test: the sweep call succeeds."""
    names = [h.name for h in _perm("external/ExternalHandler.sol")]
    assert names == ["makeExternalCalls"]


def test_role_gated_handler_is_not_permissive() -> None:
    """OrderHandler is onlyOrderKeeper/onlyController throughout."""
    perm = _perm("exchange/OrderHandler.sol")
    # only simulation helpers may appear; nothing that mutates real state
    assert all("simulate" in n.lower() for n in [h.name for h in perm])


def test_multichain_routers_expose_bridge_entries() -> None:
    """Matches the earlier hand analysis: bridgeIn/bridgeOut are permissionless."""
    names = {h.name for h in _perm("multichain/MultichainTransferRouter.sol")}
    assert {"bridgeIn", "bridgeOut"} <= names


def test_view_and_pure_functions_are_excluded() -> None:
    """The real property: a `view`/`pure` entry point is never a candidate,
    even when its body contains a call that looks like value movement."""
    src = os.path.join(GMX, "external/ExternalHandler.sol")
    names = {h.name for h in analyze_file(src)}
    assert "serialize" not in names, "view function must not be a candidate"
    hits = analyze_file(os.path.join(GMX, "fee/FeeDistributor.sol"))
    assert "getFeeAmount" not in {h.name for h in hits}
    for rel in ("router/ExchangeRouter.sol", "fee/FeeDistributor.sol",
                "exchange/OrderHandler.sol", "external/ExternalHandler.sol"):
        for h in analyze_file(os.path.join(GMX, rel)):
            assert h.name and h.line > 0
