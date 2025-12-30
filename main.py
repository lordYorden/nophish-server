from fastapi import FastAPI, HTTPException, Depends
# from contextlib import asynccontextmanager
from models import BaseSmsMessage, SmsMessage, BaseNotification, Notification, BaseReleventInfo, ReleventInfo
import uuid
from db import init_db, get_session
from sqlmodel import Session, select
from fastapi_pagination import Page, add_pagination
from fastapi_pagination.ext.sqlmodel import paginate
from hashlib import sha256

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
    
    #if timestamp and title are the same as an existing message, do not add
    existing_notif = session.exec(
        select(Notification).where(
            (Notification.timestamp == to_upload.timestamp) &
            (Notification.title == to_upload.title)
        )
    ).first()
    
    if existing_notif:
        return existing_notif
    
    session.add(notif)
    
    session.commit()
    session.refresh(notif)
    return notif


def to_hash_sha256(data: str) -> str:
    hash_object = sha256(data.encode('utf-8'))
    return hash_object.hexdigest()

@app.post("/notifications/rel")
async def upload_notfication(to_upload: BaseReleventInfo, session: Session = Depends(get_session)) -> ReleventInfo:
    id: str = str(uuid.uuid4())
    notif = ReleventInfo(id=id, **to_upload.model_dump())
    
    #check for existing
    existing_notif = session.exec(
        select(ReleventInfo).where(
            (ReleventInfo.hash == to_upload.hash)
        )
    ).first()
    
    if existing_notif:
        return existing_notif
    
    
    session.add(notif)
    session.commit()
    session.refresh(notif)
    return notif

@app.get("/notifications/byPackage/{package_name}")
async def get_notifications(package_name: str, session: Session = Depends(get_session)) -> Page[Notification]:
    return paginate(session=session,
                    query=select(Notification).where(Notification.packageName == package_name))

@app.get("/notifications")
async def get_notifications(session: Session = Depends(get_session)) -> Page[Notification]:
    return paginate(session=session,query=select(Notification))

if __name__ == "__main__":

    import uvicorn
    uvicorn.run(app, host="localhost", port=8000, log_level="debug")


