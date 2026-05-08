from pydantic import ConfigDict
from sqlalchemy import BigInteger, Column
from sqlmodel import SQLModel, Field
from typing import Optional, List

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
    title: Optional[str] = None
    body: str
    packageName: str
    timestamp: int
    contentHash: str
    urls: List[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="forbid")


class NotificationAccepted(SQLModel):
    accepted: bool
    eventId: str


class BaseReleventInfo(SQLModel):
    eventId: str = Field(unique=True)
    sourceUserId: str
    packageName: str
    timestamp: int = Field(sa_column=Column(BigInteger, nullable=False))
    contentHash: str


class ReleventInfo(BaseReleventInfo, table=True):
    id: str = Field(default=None, primary_key=True)
