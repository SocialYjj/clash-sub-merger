"""Single application-wide SlowAPI limiter."""

from slowapi import Limiter
from slowapi.util import get_remote_address

from core.config import AppConfig


limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[AppConfig.RATE_LIMIT_DEFAULT],
)
