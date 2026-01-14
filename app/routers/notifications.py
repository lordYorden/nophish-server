import uuid
from fastapi import APIRouter, Depends
from sqlmodel import Session, select, delete
from fastapi_pagination import Page
from fastapi_pagination.ext.sqlmodel import paginate
from app.database import get_session, get_redis_pool
from arq.connections import ArqRedis
from app.scheme.notification import BaseNotification, Notification, BaseReleventInfo, ReleventInfo

router = APIRouter(prefix="/notifications", tags=["notifications"])

@router.post("", response_model=Notification)
async def upload_notification(to_upload: BaseNotification, session: Session = Depends(get_session)) -> Notification:
    # if timestamp and title are the same as an existing message, do not add
    existing_notif = session.exec(
        select(Notification).where(
            (Notification.timestamp == to_upload.timestamp) &
            (Notification.title == to_upload.title)
        )
    ).first()
    
    if existing_notif:
        return existing_notif
    
    id: str = str(uuid.uuid4())
    notif = Notification(id=id, **to_upload.model_dump())
    session.add(notif)
    session.commit()
    session.refresh(notif)
    return notif

@router.get("/byPackage/{package_name}", response_model=Page[Notification])
async def get_notifications_by_package(package_name: str, session: Session = Depends(get_session)) -> Page[Notification]:
    return paginate(session=session, query=select(Notification).where(Notification.packageName == package_name))

@router.get("", response_model=Page[Notification])
async def get_notifications(session: Session = Depends(get_session)) -> Page[Notification]:
    return paginate(session=session, query=select(Notification))
    
@router.post("/rel", response_model=ReleventInfo)
async def upload_relevant_info(to_upload: BaseReleventInfo,
                                session: Session = Depends(get_session),
                                pool: ArqRedis = Depends(get_redis_pool)) -> ReleventInfo:
    # check for existing
    existing_notif = session.exec(
        select(ReleventInfo).where(
            (ReleventInfo.hash == to_upload.hash)
        )
    ).first()
    
    if existing_notif:
        return existing_notif
    
    id: str = str(uuid.uuid4())
    notif = ReleventInfo(id=id, **to_upload.model_dump())
    session.add(notif)
    session.commit()
    session.refresh(notif)

    await pool.enqueue_job("detector_pipeline", notif)

    return notif

@router.get("/rel", response_model=Page[ReleventInfo])
async def get_notifications(session: Session = Depends(get_session)) -> Page[ReleventInfo]:
    return paginate(session=session, query=select(ReleventInfo))


@router.delete("/rel", status_code=204)
async def delete_all_relevant_info(session: Session = Depends(get_session)):
    session.exec(delete(ReleventInfo))
    session.commit()
    return