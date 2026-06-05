import re

from pydantic import ConfigDict, field_validator
from sqlalchemy import BigInteger, Column
from sqlmodel import SQLModel, Field
from typing import Optional, List

_FCM_TOPIC_ID_RE = re.compile(r"^[A-Za-z0-9_.~%-]+$")

class BaseNotification(SQLModel):
    title: str
    extraTitle: Optional[str]
    isGroup: Optional[bool]
    body: Optional[str]
    timestamp: Optional[int]
    packageName: Optional[str]
    
class Notification(BaseNotification, table=True):
    id: str = Field(default=None, primary_key=True)
    
class NotificationSubmission(SQLModel):
    eventId: str
    sourceUserId: str
    circleId: str
    title: Optional[str] = None
    body: str
    packageName: str
    timestamp: int
    contentHash: str
    urls: List[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")

    @field_validator("circleId")
    @classmethod
    def validate_circle_id(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("circleId must not be empty")
        if not _FCM_TOPIC_ID_RE.fullmatch(value):
            raise ValueError("circleId contains characters that are not valid in an FCM topic")
        return value


class NotificationAccepted(SQLModel):
    accepted: bool
    eventId: str


class BaseReleventInfo(SQLModel):
    eventId: str = Field(unique=True)
    sourceUserId: str
    circleId: str
    packageName: str
    timestamp: int = Field(sa_column=Column(BigInteger, nullable=False))
    contentHash: str
    alerted: bool = False


class ReleventInfo(BaseReleventInfo, table=True):
    id: str = Field(default=None, primary_key=True)
