import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from fastapi_pagination import Page
from fastapi_pagination.ext.sqlmodel import paginate
from app.database import get_session
from app.scheme.message import BaseSmsMessage, SmsMessage

router = APIRouter(prefix="/messages", tags=["messages"])

@router.post("", response_model=SmsMessage)
async def upload_msg(to_upload: BaseSmsMessage, session: Session = Depends(get_session)) -> SmsMessage:
    id: str = str(uuid.uuid4())
    msg = SmsMessage(id=id, **to_upload.model_dump())
    session.add(msg)
    session.commit()
    session.refresh(msg)
    return msg

@router.get("", response_model=Page[SmsMessage])
async def get_messages(session: Session = Depends(get_session)) -> Page[SmsMessage]:
    return paginate(session=session, query=select(SmsMessage))

@router.get("/{message_id}", response_model=SmsMessage)
async def get_message(message_id: str, session: Session = Depends(get_session)) -> SmsMessage:
    msg = session.get(SmsMessage, message_id)
    if msg is None:
        raise HTTPException(status_code=404, detail=f"Message with id: {message_id} was not found!")
    return msg

@router.get("/byNumber/{phone_number}", response_model=Page[SmsMessage])
async def get_messages_by_number(phone_number: str, session: Session = Depends(get_session)) -> Page[SmsMessage]:
    return paginate(session=session, query=select(SmsMessage).where(SmsMessage.phone_number == phone_number))
