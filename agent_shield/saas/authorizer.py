# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""OpenFGA through IAM (SH-75): the ``openfga-through-iam`` contribution to the port.

On Datalayer the Shield never holds OpenFGA's address or credentials: it asks
IAM's evaluation route — ``POST /api/iam/v1/authz/evaluate``, AuthZen's shape
in and out — with the runtime's or the registered Shield's token, and IAM asks
OpenFGA. The answer's ``context`` carries the model's version
(``model_version``) and the reason, which the audit records with the
decision. The port's rules are :mod:`agent_shield.policy.authorize`'s: a deny
wins, unreachable is a deny, allows are cached until they expire.
"""

from __future__ import annotations

from collections.abc import Callable

from agent_shield.policy import AuthZenAuthorizer

#: IAM's AuthZen evaluation route, under its API prefix.
EVALUATE_PATH = "/api/iam/v1/authz/evaluate"


def evaluate_url(iam_url: str) -> str:
    return iam_url.rstrip("/") + EVALUATE_PATH


class IamAuthorizer(AuthZenAuthorizer):
    """IAM's evaluation route, with the token: the one authorizer on Datalayer."""

    def __init__(self, iam_url: str, token: Callable[[], str] | str, *, timeout: float = 5.0) -> None:
        if not iam_url:
            raise ValueError("IAM's URL is needed to ask it for an authorization")
        if not token:
            raise ValueError("a token is needed to ask IAM for an authorization")
        super().__init__(evaluate_url(iam_url), name="openfga-through-iam", token=token, timeout=timeout)
        self.iam_url = iam_url.rstrip("/")


__all__ = ["EVALUATE_PATH", "IamAuthorizer", "evaluate_url"]
