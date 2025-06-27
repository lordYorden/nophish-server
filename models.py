from pydantic import BaseModel
from sqlmodel import SQLModel, Field
from typing import Optional

class BaseSmsMessage(SQLModel):
    phone_number: str
    body: Optional[str]
    timestamp: Optional[int]
    
class SmsMessage(BaseSmsMessage, table=True):
    id: str = Field(default=None, primary_key=True)
    
class BaseNotification(SQLModel):
    title: str
    body: Optional[str]
    timestamp: Optional[int]
    
class Notification(BaseNotification, table=True):
    id: str = Field(default=None, primary_key=True)