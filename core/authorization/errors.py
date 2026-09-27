"""Typed authorization / historical-key failures (prototype-level)."""

from __future__ import annotations


class HistoricalAttributeKeyUnavailable(LookupError):
    """No user attribute material for the requested attrStateId."""


class HistoricalRoleKeyUnavailable(LookupError):
    """No user role material for the requested roleStateId."""


class AuthorizationStateMismatch(ValueError):
    """Requested authorization state id does not match stored key material."""


class AuthorizationUpdateRejected(RuntimeError):
    """Fabric (or standalone ledger) rejected UpdateAuthorization; active unchanged."""
