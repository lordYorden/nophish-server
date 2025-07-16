from fastapi import FastAPI, HTTPException, Depends
# from contextlib import asynccontextmanager
from models import BaseSmsMessage, SmsMessage, BaseNotification, Notification
import uuid
from db import init_db, get_session
from sqlmodel import Session, select
from fastapi_pagination import Page, add_pagination
from fastapi_pagination.ext.sqlmodel import paginate

# @asynccontextmanager
# async def lifespan(app: FastAPI):
#     #init_db()
#     yield

app = FastAPI()
add_pagination(app)
    
@app.get("/")
async def root():
    return {"Hello": "World"}

@app.post("/messages")
async def upload_msg(to_upload: BaseSmsMessage, session: Session = Depends(get_session)) -> SmsMessage:
    id: str = str(uuid.uuid4())
    msg = SmsMessage(id=id, **to_upload.model_dump())
    session.add(msg)
    
    session.commit()
    session.refresh(msg)
    return msg

@app.get("/messages")
async def get_messages(session: Session = Depends(get_session)) -> Page[SmsMessage]:
    return paginate(session=session,
                    query=select(SmsMessage))

@app.get("/messages/{message_id}")
async def get_messages(message_id: str, session: Session = Depends(get_session)) -> SmsMessage:
    msg = session.get(SmsMessage, message_id)
    if msg is None:
        raise HTTPException(status_code=404, detail=f"Message with id: {message_id} was not found!")
    
    return msg

@app.get("/messages/byNumber/{phone_number}")
async def get_messages(phone_number: str, session: Session = Depends(get_session)) -> Page[SmsMessage]:
    return paginate(session=session, 
                    query=select(SmsMessage).where(SmsMessage.phone_number == phone_number))
    
    
@app.post("/notifications")
async def upload_notfication(to_upload: BaseNotification, session: Session = Depends(get_session)) -> Notification:
    id: str = str(uuid.uuid4())
    notif = Notification(id=id, **to_upload.model_dump())
    session.add(notif)
    
    session.commit()
    session.refresh(notif)
    return notif

@app.get("/notifications")
async def get_notifications(session: Session = Depends(get_session)) -> Page[Notification]:
    return paginate(session=session,
                    query=select(Notification))

