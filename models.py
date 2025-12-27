from pydantic import BaseModel
from sqlmodel import SQLModel, Field
from typing import Optional, List
from sqlalchemy import Column, JSON

class BaseSmsMessage(SQLModel):
    phone_number: str
    body: Optional[str]
    timestamp: Optional[int]
    
class SmsMessage(BaseSmsMessage, table=True):
    id: str = Field(default=None, primary_key=True)
    
class BaseNotification(SQLModel):
    title: str
    extraTitle: Optional[str]
    isGroup: Optional[bool]
    body: Optional[str]
    timestamp: Optional[int]
    packageName: Optional[str]
    
class Notification(BaseNotification, table=True):
    id: str = Field(default=None, primary_key=True)
    
class BaseReleventInfo(SQLModel):
    body: Optional[str]
    packageName: Optional[str]
    hash: Optional[str]
    urls: Optional[List[str]] = Field(default=None, sa_column=Column(JSON))
class ReleventInfo(BaseReleventInfo, table=True):
    id: str = Field(default=None, primary_key=True)
    

    