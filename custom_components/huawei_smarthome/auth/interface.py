"""Authentication provider interface and interactive login results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..domain.models import AuthSession

CHALLENGE_KIND_DEVICE = "device"
CHALLENGE_KIND_SMS = "sms"
CHALLENGE_KIND_EMAIL = "email"

_SMS_ACCOUNT_TYPES = frozenset({"2", "6"})
_EMAIL_ACCOUNT_TYPES = frozenset({"1", "5"})
_DEVICE_ACCOUNT_TYPES = frozenset({"-1"})


@dataclass(frozen=True, slots=True)
class ChallengeChannel:
    """One verification channel offered by the Huawei challenge response."""

    name: str
    account_type: str
    kind: str
    sent: bool

    @property
    def key(self) -> str:
        """Stable identifier used as the selector value in the config flow."""

        return f"{self.kind}:{self.account_type}:{self.name}"

    @property
    def is_sms(self) -> bool:
        return self.kind == CHALLENGE_KIND_SMS


def channel_kind(account_type: object) -> str:
    """Classify an ``authCodeSentList`` entry into a delivery channel kind."""

    value = str(account_type)
    if value in _SMS_ACCOUNT_TYPES:
        return CHALLENGE_KIND_SMS
    if value in _EMAIL_ACCOUNT_TYPES:
        return CHALLENGE_KIND_EMAIL
    if value in _DEVICE_ACCOUNT_TYPES:
        return CHALLENGE_KIND_DEVICE
    return CHALLENGE_KIND_DEVICE


@dataclass(frozen=True, slots=True)
class LoginChallenge:
    """Challenge information shown to the user."""

    prompt: str
    challenge_name: str
    challenge_type: str
    channels: tuple[ChallengeChannel, ...] = ()


@dataclass(frozen=True, slots=True)
class LoginStart:
    """Result of starting an account login."""

    session: AuthSession | None = None
    challenge: LoginChallenge | None = None


class AuthProvider(Protocol):
    """Port for Huawei account authentication."""

    async def async_begin_login(self, account: str, password: str) -> LoginStart:
        """Start account/password login."""

    async def async_select_challenge_channel(
        self,
        channel: ChallengeChannel,
    ) -> LoginChallenge:
        """Choose a verification channel and dispatch its code."""

    async def async_complete_challenge(self, code: str) -> AuthSession:
        """Complete a pending device challenge."""

    async def async_refresh_oauth(self, session: AuthSession) -> AuthSession:
        """Refresh the OAuth session token with the Huawei service token."""

    async def async_refresh_hms_lite(self, session: AuthSession) -> AuthSession:
        """Reissue the HMS-lite token through the Huawei silent-auth flow."""
