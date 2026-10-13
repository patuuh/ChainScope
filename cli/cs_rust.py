"""Rust-native Critical detectors for Substrate/FRAME pallets.

The 21 Veck classes are Solidity-only (`_SOL = {".sol"}`), so they provide zero
coverage of a Substrate chain. That matters now that Hydration - the largest
Immunefi ceiling in the catalog at 222,222 - is 71 `.rs` files, 35,849 lines, and
nothing in this toolchain read any of it.

Two classes here, both earning their place by having actually found something:

R1  debug_assert standing in for a security invariant.

    A Substrate production runtime is release WASM, and `debug_assert!` compiles
    out of it. So a `debug_assert!` that is the *only* enforcement of an
    invariant protects nothing in production. Hydration's stableswap had exactly
    this on the share ledger until commit 50a55673c4 (2026-07-15).

    The discrimination is the hard part and the reason a grep is not enough.
    This is a **false positive**:

        let r: DispatchResult = (|| { ensure!(x >= y, Err); Ok(()) })();
        debug_assert!(r.is_ok(), "invariant");
        r                                  // the Result is returned and enforced

    and this is a **real finding**:

        fn ensure_issuance_in_sync(id) {
            debug_assert_eq!(tracked, total, "...");   // returns ()
        }

    Both contain `debug_assert`. The difference is whether an `ensure!`/`?`
    produces a value the caller receives. So R1 requires the guarded function to
    return unit, or to return something that never carries the check.

R2  Share price derived from a raw balance (donation / first-depositor).

    The Solidity class 19 translated into Rust, and the family this hunt hit three
    times: IPOR PowerToken, Gamma Hypervisor, Gamma xGamma. All three died on the
    same economics - the attacker needs f -> 1 of supply - so R2 exists to find
    the *instances*, not to imply they are exploitable.
"""

from __future__ import annotations

import re
import typing as t
from pathlib import Path

RUST = {".rs"}

_RUST_SKIP_DIRS = frozenset({
    "target", "node_modules", ".git", "vendor", "out", "dist", "build",
    "tests", "test", "benches", "fixtures", "__pycache__",
})

# --------------------------------------------------------------------- R1

# A function that returns unit cannot propagate a check, so a debug_assert inside
# it is the sole enforcement. Matches `-> ()`, `fn f(...) {`, and `pub fn`.
_UNIT_FN = re.compile(r"(?:pub(?:\([^)]*\))?\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\([^)]*\)\s*(?:->\s*\(\s*\)\s*)?\{")
_DEBUG_ASSERT = re.compile(r"\bdebug_assert(?:!|_eq!|_ne!)\s*\(")
# Something that could carry a failure out of the function.
_ENFORCING = re.compile(r"\bensure!\s*\(|\?;|\.ok_or|->\s*Result|->\s*DispatchResult|Err\(")

# `#[cfg(not(debug_assertions))]`-only tests tell you a panic path was deliberately
# split out; that is a strong hint the authors knew the production path differed.
_CFG_RELEASE_ONLY = re.compile(r"#\s*\[\s*cfg\s*\(\s*not\s*\(\s*debug_assertions\s*\)\s*\)\s*\]")


def rust_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*"):
        if p.suffix not in RUST or not p.is_file():
            continue
        rel = p.relative_to(root)
        if set(rel.parts[:-1]) & _RUST_SKIP_DIRS:
            continue
        out.append(p)
    return out


def _fn_bodies(text: str) -> t.Iterator[tuple[str, int, str]]:
    """Yield (fn_name, 1-based line of `fn`, brace-matched body) for every `fn`.

    Written by scanning forward from the `fn` keyword to the first `{` at paren
    depth zero, rather than regexing the signature line. The regex version only
    matched 7 of 89 `debug_assert!` sites in HydraDX-node, because FRAME
    signatures routinely span lines and the opening brace is often on its own
    line or after a multi-line `-> DispatchResult`. That undercount made a 260k
    line tree look like it had 2 findings when it had never really been examined,
    so this walks the source instead.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.search(r"\bfn\s+(\w+)", line)
        if not m:
            continue
        # scan forward for the opening brace, tracking paren depth
        depth_paren = 0
        body_start_line = None
        j = i
        while j < len(lines) and j < i + 40:
            for ch in lines[j]:
                if ch in "([":
                    depth_paren += 1
                elif ch in ")]":
                    depth_paren -= 1
                elif ch == "{" and depth_paren <= 0:
                    body_start_line = j
                    break
            if body_start_line is not None:
                break
            j += 1
        if body_start_line is None:
            continue  # trait declaration, or a signature we cannot close
        depth = 0
        started = False
        body: list[str] = []
        for ln in lines[body_start_line:]:
            body.append(ln)
            for ch in ln:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
            if started and depth <= 0:
                break
            if len(body) > 4000:
                break  # pathological; do not let one file stall the sweep
        yield m.group(1), i + 1, "\n".join(body)


def scan_debug_assert(root: Path) -> list[dict[str, t.Any]]:
    """R1: a `debug_assert!` that is the only enforcement in a unit-returning fn."""
    hits: list[dict[str, t.Any]] = []
    for f in rust_files(root):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for name, line_no, body in _fn_bodies(text):
            if not _DEBUG_ASSERT.search(body):
                continue
            # If the body can carry a failure out, the debug_assert is diagnostic.
            if _ENFORCING.search(body):
                continue
            # A bare `debug_assert!(false, ...)` is usually an unreachable arm,
            # not an invariant. Keep it but mark it lower-confidence.
            snippet = ""
            asserted: set[str] = set()
            for ln in body.splitlines():
                if _DEBUG_ASSERT.search(ln):
                    snippet = ln.strip()
                    # names the assert actually guards
                    # No length filter: single-char names are extremely common
                    # in this math code (`b`, `x`, `r`) and dropping them silently
                    # disabled the saturating-arithmetic demotion entirely.
                    asserted |= {w for w in re.findall(r"\b([a-z_][a-z0-9_]*)\b", ln)
                                 if not w.endswith(("_assert", "debug"))}
            # If a guarded name is consumed by saturating_* arithmetic the assert
            # documents a precondition: the arithmetic degrades safely instead of
            # panicking, so it is not a missing production check.
            saturated = bool(re.search(r"saturating_(?:add|sub|mul|div|pow)", body))
            hint = "high"
            if "debug_assert!(false" in body:
                hint = "low"
            elif saturated and any(re.search(rf"saturating_\w*\(\s*&?{re.escape(n)}\b", body)
                                     for n in asserted):
                hint = "low"
            hits.append({
                "class_id": "R1",
                "class": "debug_assert as sole invariant enforcement (absent from release WASM)",
                "fn": name,
                "file": str(f),
                "line": line_no,
                "snippet": snippet,
                "severity_hint": hint,
            })
    return hits


# --------------------------------------------------------------------- R2

# A division whose divisor is an issuance/supply figure.
_SHARE_MATH = re.compile(
    r"(?:checked_div|\.div\(|\bsdiv\b|\bper_shares?\b|\/\s*)",
    re.I,
)
# Names of figures that must not be used as a share-price denominator.
_ISSUANCE_NAME = re.compile(
    r"(?:total_supply|total_issuance|share_issuance|total_shares|total_stake|"
    r"total_bonded|issuance|supply)",
    re.I,
)
# `let supply = T::Currency::total_issuance(pool_id);` - the indirection that a
# purely syntactic scan misses. Without this the detector only fires when the
# call reads `checked_div(total_supply())` inline, which is rare in real pallet
# code and was the reason my own fixture failed.
_ISSUE_BINDING = re.compile(
    r"\blet\s+(?:mut\s+)?(\w+)\b[^=\n]*=\s*[^;\n]*?"
    r"(?:total_supply|total_issuance|share_issuance|total_shares|total_stake|issuance)\b",
    re.I,
)
# `calculate_shares(..., share_issuance: Balance)` - issuance handed in as a
# parameter rather than read from storage, as in Hydration's Curve-style math.
_ISSUE_PARAM = re.compile(r"\b(\w*(?:issuance|supply|shares)\w*)\s*:\s*(?:Balance|u128|u64|i128)", re.I)
# ... or a live balance read, which is the "total assets" side.
_BALANCE_READ = re.compile(
    r"(?:free_balance|reserved_balance|balance|total_issuance)\s*(?:\(|of\b)|\b\w+\.balance\b",
    re.I,
)
_MINIMUM_LIQUIDITY = re.compile(
    r"MINIMUM_LIQUIDITY|minimum_liquidity|virtual_shares|VIRTUAL_SHARES|VIRTUAL_ASSETS|"
    r"virtual_assets|dead_shares|burn_from_address|MINIMUM_LIQUIDITY",
    re.I,
)
_FIRST_DEPOSITOR_GUARD = re.compile(
    r"total_supply\(\)\s*(?:==|is_)\s*zero|total_issuance\s*\(\s*\)\s*(?:==|\.is_zero)|"
    r"if\s+\w*[Tt]otal\w*\s*(?:==|<=|==)\s*0",
    re.I,
)


def scan_donation_shape(root: Path) -> list[dict[str, t.Any]]:
    """R2: share/issuance math dividing by a raw balance, minus known mitigations."""
    hits: list[dict[str, t.Any]] = []
    for f in rust_files(root):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        # A file that declares a virtual-offset mitigation is largely exonerated.
        if _MINIMUM_LIQUIDITY.search(text):
            continue
        stripped = re.sub(r"//.*|/\*.*?\*/", "", text, flags=re.S)
        lines = stripped.splitlines()
        # Resolve issuance held in a local, and issuance passed as a parameter.
        # Without this the detector only fires on inline `checked_div(total_supply())`,
        # which real pallet code almost never writes.
        issuance_names = {m.group(1).lower() for m in _ISSUE_BINDING.finditer(stripped)}
        issuance_names |= {m.group(1).lower() for m in _ISSUE_PARAM.finditer(stripped)}
        for i, line in enumerate(lines, 1):
            if not _SHARE_MATH.search(line):
                continue
            window = "\n".join(lines[max(0, i - 12) : i + 2])
            if not _BALANCE_READ.search(window):
                continue
            if _FIRST_DEPOSITOR_GUARD.search(window):
                continue
            window_words = {w.lower() for w in re.findall(r"\w+", window)}
            # The mitigation has to be resolved through the same indirection as
            # the flag, or `let supply = total_supply(); if supply == 0` reads as
            # unguarded when it is exactly the guard.
            if re.search(r"\bif\s*\(?\s*\w+\s*(?:==|<=)\s*0", window) and (
                issuance_names & window_words
            ):
                continue
            # the divisor is either named in-line or one of the resolved names
            divisor_is_issuance = bool(_ISSUANCE_NAME.search(window)) and (
                bool(issuance_names & window_words)
                or bool(_ISSUANCE_NAME.search(line))
            )
            if not divisor_is_issuance:
                continue
            hits.append({
                "class_id": "R2",
                "class": "share price from raw balance, no virtual offset found in file",
                "file": str(f),
                "line": i,
                "snippet": line.strip()[:200],
                "severity_hint": "medium",
            })
    return hits


# ------------------------------------------------------------------- R3 / R4

# A `#[pallet::call]` impl block: every `pub fn` in it is a public extrinsic.
_PALLET_CALL = re.compile(r"#\s*\[\s*pallet::call\s*\]")
# The dispatch attribute in modern FRAME is `#[pallet::call_index = N]`; there is
# no `pallet::dispatch` attribute. (There was an older `#[pallet::call]`-adjacent
# form, but matching a nonexistent attribute yields silent zero results.)
# The FIRST parameter must be an origin, or this is an internal helper - matching
# any typed parameter set turns every internal fn into an "extrinsic".
_DISPATCH_FN = re.compile(
    r"(?:pub\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\(\s*"
    r"(origin\w*|o\w*)\s*:\s*(OriginFor<[^>]*>|RawOrigin<[^>]*>|T::Origin|OriginFor<[^>]*>\s*)\s*[,)]"
)
# Origin/authority gates. `ensure_origin` is the real FRAME idiom and must be
# matched on its own: gates are configured as
# `<T as Config>::AuthorityOrigin::ensure_origin(origin)`, so a literal
# `T::UpdateOrigin` never appears and every properly-gated admin extrinsic gets
# reported as ungated. Match the `<T as ...Config>::XOrigin` form too.
_ORIGIN_GATE = re.compile(
    r"ensure_signed|ensure_root|ensure_none|ensure_signed_or_root|"
    r"ensure_origin\s*\(|"
    r"::\s*[A-Za-z0-9_]*Origin\s*::\s*ensure_origin|"
    r"RawOrigin|RawOriginWithSuccess|origin\.caller|"
    r"ensure!\s*\(\s*origin",
    re.I,
)
# A mutator: writes storage, moves balance, or mutates a pool/account.
_MUTATION = re.compile(
    r"(?:<[^>]*>::(?:insert|remove|mutate|try_mutate|append|take_from|mutate_exists)\b"
    r"|\.(?:insert|remove|mutate|try_mutate|mutate_exists)\s*\(|"
    r"T::Currency::(?:transfer|deposit_into_existing|withdraw|make_free_balance|slash_stash)"
    r"|DepositFee|transfer_assets|Xcm::|set_(?:fee|price|rate|parameter|admin|owner)\b"
    r"|TotalIssuance::|ShareIssuance::|mutate_account)",
    re.I,
)
# Administrative read-only configuration writes that use their own gate style.
_ADMIN_WRITE = re.compile(r"\bset_[a-z_]+\s*\(|\bupdate_[a-z_]+\s*\(")


def scan_missing_origin_gate(root: Path) -> list[dict[str, t.Any]]:
    """R3: a public extrinsic that mutates state with no origin/authority gate.

    FRAME's `#[pallet::call]` makes an extrinsic public by default; the gate is
    whatever the body checks. A mutator with no `ensure_signed!`/`ensure_root!`/
    `T::UpdateOrigin` is either intentionally permissionless (a real design
    choice, e.g. anyone may `swap`) or an access-control hole. Nothing in the
    signature distinguishes them, which is exactly why it needs surfacing.
    """
    hits: list[dict[str, t.Any]] = []
    for f in rust_files(root):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        if not _PALLET_CALL.search(text):
            continue
        # Every `fn` in a `#[pallet::call]` impl is a public extrinsic; the body
        # is brace-matched rather than windowed, because a 3000-char window is
        # both too short for a large extrinsic and too long to attribute a gate.
        for fname, line_no, body in _fn_bodies(text):
            sig_m = _DISPATCH_FN.match(body.splitlines()[0].strip() if body else "")
            if not sig_m or not _MUTATION.search(body):
                continue
            if _ORIGIN_GATE.search(body):
                continue
            hits.append({
                "class_id": "R3",
                "class": "mutating extrinsic with no origin/authority gate found",
                "fn": fname,
                "file": str(f),
                "line": line_no,
                "snippet": body.splitlines()[0].strip()[:160],
                "severity_hint": "needs-triage",  # permissionless is often intended
            })
    return hits


# Errors discarded on a call that moves value. `.ok()`, `let _ =`, `unwrap_or_default`,
# `unwrap_or(0)` and a bare `;` on a Result all swallow the reason.
_SWALLOW = re.compile(r"\.ok\(\s*\)|let\s+_\s*=|\.unwrap_or_default\(\)|\.unwrap_or_else\(\|\s*\|\s*\w*\s*\)")
_VALUE_CALL = re.compile(
    r"(?:T::Currency|Currency)::(?:transfer|transfer_all|withdraw|slash_stash|deposit_into_existing|"
    r"make_free_balance|repatriate_reserved_balance|transfer_assets|deposit_fee|burn\w*)\s*\("
    r"|(?:DepositFee|DepositAll|Reserve|ReserveSchema)::deposit_fee\s*\(",
    re.I,
)


def scan_swallowed_value_error(root: Path) -> list[dict[str, t.Any]]:
    """R4: a currency/asset movement whose Result is discarded.

    A failed transfer that is swallowed is a silent accounting loss or a stranded
    balance. This fires on shape, not intent: `let _ = x.transfer(..)` is the same
    whether the author meant to ignore it or did not realise it was a Result.
    """
    hits: list[dict[str, t.Any]] = []
    for f in rust_files(root):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            if not _VALUE_CALL.search(line):
                continue
            # Statement window: FRAME calls are routinely wrapped over several
            # lines, and the `?` that decides whether the Result was swallowed is
            # usually on the *closing* line. Checking only the opening line
            # flags every multi-line `let _ = ...burn_from(...)?` as swallowed.
            stmt = ""
            for j in range(i - 1, min(i + 14, len(lines))):
                stmt += " " + lines[j].strip()
                if ");" in lines[j] or ")" in lines[j] and ";" in lines[j]:
                    break
            if not _SWALLOW.search(stmt):
                continue
            # A log-and-propagate is not swallowing. `?` anywhere in the
            # statement means the Result reaches the caller.
            if re.search(r"\?(\s*[,;)]|$)", stmt) or re.search(r"\|\s*else|if\s+let\s+Err", stmt):
                continue
            hits.append({
                "class_id": "R4",
                "class": "value movement with a discarded Result",
                "file": str(f),
                "line": i,
                "snippet": re.sub(r"\s+", " ", stmt).strip()[:200],
                "severity_hint": "needs-triage",
            })
    return hits


# --------------------------------------------------------------------------- R5
#
# Grounded in Hydration's own published post-mortem, not guesswork. Their
# checklist theme #11: "saturating_sub/saturating_* hiding errors - saturating
# math silently returns 0 on underflow instead of failing. This has led to
# critical exploits where insufficient balances were silently accepted."
#
# The $500k aToken Critical was exactly that:
#
#     let diff = atoken_balance.saturating_sub(amount);   // amount is user-supplied
#
# so aToken transfers never failed for insufficient balance - saturating to 0
# selected a "withdraw all" branch instead.
#
# But saturating arithmetic is NOT per se the bug. In the same pallet:
#
#     let remaining = MultiCurrency::unreserve_named(id, cur, who, value);
#     let unreserved = value.saturating_sub(remaining);
#
# both operands derive from one operation and `remaining <= value` by
# construction, so it can never saturate. Flagging that would be noise.
#
# The dangerous form is specifically: saturating arithmetic where one operand is
# a *stored balance* and the other is an *externally supplied amount*. That is
# the shape that turned an underflow into silent value creation.

_BALANCE_OPERAND = re.compile(
    r"(?:\b\w*balance\w*|\bfree_balance\b|\btotal_balance\b|\breserved\b|\bissuance\w*|\bdebt\b|"
    r"\bcollateral\w*|\bamount_available\b|\bfunds\b)\s*$",
    re.I,
)
# A function parameter that names an amount/value supplied by a caller.
_AMOUNT_PARAM = re.compile(
    r"\b(amount|value|qty|quantity|total|bonded|stake|weight|shares?)\w*\s*:\s*", re.I
)
_SATURATING = re.compile(
    r"\b(?P<lhs>\w[\w.:\[\]()]*?)\.saturating_(?P<op>add|sub|mul|div|pow)\s*\(\s*(?P<rhs>[^;]*)\)"
)


def scan_saturating_on_supplied_amount(root: Path) -> list[dict[str, t.Any]]:
    """R5: `saturating_*` between a stored balance and a caller-supplied amount.

    The exact shape behind Hydration's $500k aToken Critical. Deliberately narrow:
    requiring a balance-named operand on one side and an amount parameter in
    scope on the other keeps it off the same-operation `value - remaining` idiom
    in `currencies::unreserve_named`, which cannot underflow.
    """
    hits: list[dict[str, t.Any]] = []
    for f in rust_files(root):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for fname, line_no, body in _fn_bodies(text):
            supplied = {m.group(1).lower() for m in _AMOUNT_PARAM.finditer(body.split("{", 1)[0])}
            if not supplied:
                continue
            for ln_no, line in enumerate(body.splitlines(), 1):
                for m in _SATURATING.finditer(line):
                    lhs, rhs = m.group("lhs").strip(), m.group("rhs").strip()
                    # normalise trailing method chains e.g. `self.free_balance(a)`
                    lhs_leaf = re.split(r"[.:(]", lhs)[-1]
                    rhs_leaf = re.split(r"[.:(]", rhs)[-1] if rhs else ""
                    bal_side = bool(_BALANCE_OPERAND.search(lhs)) or bool(
                        _BALANCE_OPERAND.search(rhs)
                    )
                    sup_side = (
                        lhs_leaf.lower() in supplied
                        or rhs_leaf.lower() in supplied
                        or any(re.search(rf"\b{re.escape(s)}\b", lhs + rhs) for s in supplied)
                    )
                    if bal_side and sup_side:
                        hits.append({
                            "class_id": "R5",
                            "class": "saturating math between a stored balance and a supplied amount",
                            "fn": fname,
                            "file": str(f),
                            "line": line_no + ln_no,
                            "snippet": line.strip()[:200],
                            "severity_hint": "high",
                        })
    return hits


# ------------------------------------------------------------------- driver

SCANNERS = {
    "R1": scan_debug_assert,
    "R2": scan_donation_shape,
    "R3": scan_missing_origin_gate,
    "R4": scan_swallowed_value_error,
    "R5": scan_saturating_on_supplied_amount,
}


def scan(
    root: Path, classes: list[str] | None = None
) -> list[dict[str, t.Any]]:
    out: list[dict[str, t.Any]] = []
    for cid, fn in SCANNERS.items():
        if classes and cid not in classes:
            continue
        try:
            out.extend(fn(root))
        except Exception as exc:  # never let one bad file kill the sweep
            out.append({"class_id": cid, "error": f"{type(exc).__name__}: {exc}"})
    return out


def summary(root: Path, classes: list[str] | None = None) -> dict[str, int]:
    counts: dict[str, int] = {}
    for h in scan(root, classes):
        key = str(h.get("class_id"))
        counts[key] = counts.get(key, 0) + 1
    return counts