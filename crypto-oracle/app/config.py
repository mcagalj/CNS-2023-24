from functools import lru_cache
from typing import Literal

from glom import glom
from pydantic import Field
from pydantic_settings import BaseSettings
from typing_extensions import Annotated
from yaml import load
from yaml.loader import SafeLoader

with open("settings.yaml") as f:
    settings = load(f, Loader=SafeLoader)


class AppSettings(BaseSettings):
    app_title: str = glom(settings, "app.title")
    app_username: str = glom(settings, "app.username")
    jwt_secret_key: str = glom(settings, "app.jwt_secret_key")
    jwt_algorithm: Literal["HS256", "HS512"] = glom(settings, "app.jwt_algorithm")
    key_seed: str = glom(settings, "app.key_seed")
    max_plaintext_size: int = glom(settings, "app.max_plaintext_size")


class ARP(BaseSettings):
    prefix: str = "/arp"
    scope: Literal["arp"] = glom(settings, "lab.arp.scope")
    cookie: str = glom(settings, "lab.arp.cookie")
    challenge: str = glom(settings, "lab.arp.challenge")
    password: str = glom(settings, "lab.arp.password")


class VERNAM(BaseSettings):
    prefix: str = "/vernam"
    scope: Literal["vernam"] = glom(settings, "lab.vernam.scope")
    challenge: str = glom(settings, "lab.vernam.challenge")
    password: str = glom(settings, "lab.vernam.password")
    key_size: int = glom(settings, "lab.vernam.key_size")


class ECB(BaseSettings):
    prefix: str = "/ecb"
    scope: Literal["ecb"] = glom(settings, "lab.ecb.scope")
    cookie: str = glom(settings, "lab.ecb.cookie")
    challenge: str = glom(settings, "lab.ecb.challenge")
    password: str = glom(settings, "lab.ecb.password")


class CBC(BaseSettings):
    prefix: str = "/cbc"
    scope: Literal["cbc"] = glom(settings, "lab.cbc.scope")
    cookie: str = glom(settings, "lab.cbc.cookie")
    challenge: str = glom(settings, "lab.cbc.challenge")
    password: str = glom(settings, "lab.cbc.password")
    iv_increment: int = glom(settings, "lab.cbc.iv_increment")


class CTR(BaseSettings):
    prefix: str = "/ctr"
    scope: Literal["ctr"] = glom(settings, "lab.ctr.scope")
    challenge: str = glom(settings, "lab.ctr.challenge")
    password: str = glom(settings, "lab.ctr.password")
    difficulty: Annotated[int, Field(gt=8, lt=16)] = glom(
        settings, "lab.ctr.difficulty"
    )


class ASYMMETRIC(BaseSettings):
    prefix: str = "/asymmetric"
    scope: Literal["asymmetric"] = glom(settings, "lab.asymmetric.scope")
    challenge: str = glom(settings, "lab.asymmetric.challenge")
    password: str = glom(settings, "lab.asymmetric.password")
    key_size: int = glom(settings, "lab.asymmetric.key_size")


class TLS(BaseSettings):
    prefix: str = "/tls"


class PASSKEYS(BaseSettings):
    prefix: str = "/passkeys"
    rp_name: str = glom(settings, "lab.passkeys.rp_name")


arp = ARP()
vernam = VERNAM()
ecb = ECB()
cbc = CBC()
ctr = CTR()
asymmetric = ASYMMETRIC()
tls = TLS()
passkeys = PASSKEYS()


# Set password order here
LAB_ORDER = [arp, vernam, ecb, cbc, ctr, asymmetric]
# LAB_ORDER = [arp, vernam, ecb, cbc, ctr]

for lab in LAB_ORDER:
    lab_index = LAB_ORDER.index(lab)
    if lab_index < len(LAB_ORDER) - 1:
        next_lab = LAB_ORDER[lab_index + 1]
        lab.challenge = (
            f"{lab.challenge} ({next_lab.scope.upper()}: {next_lab.password})"
        )


@lru_cache()
def get_app_settings() -> AppSettings:
    return AppSettings()
