import uuid
import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select, delete
from fastapi_pagination import Page
from fastapi_pagination.ext.sqlmodel import paginate
from app.database import get_session, get_redis_pool
from arq.connections import ArqRedis
from app.scheme.notification import (
    BaseNotification,
    Notification,
    NotificationAccepted,
    NotificationSubmission,
    ReleventInfo,
)

router = APIRouter(prefix="/notifications", tags=["notifications"])
logger = logging.getLogger("uvicorn.error")

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
    
@router.post("/rel", response_model=NotificationAccepted)
async def upload_relevant_info(
    to_upload: NotificationSubmission,
    session: Session = Depends(get_session),
    pool: ArqRedis = Depends(get_redis_pool),
) -> NotificationAccepted:
    existing_notif = session.exec(
        select(ReleventInfo).where(
            (ReleventInfo.eventId == to_upload.eventId)
        )
    ).first()

    if existing_notif:
        logger.info(
            "Duplicate notification submission ignored: eventId=%s sourceUserId=%s packageName=%s timestamp=%s",
            to_upload.eventId,
            to_upload.sourceUserId,
            to_upload.packageName,
            to_upload.timestamp,
        )
        return NotificationAccepted(accepted=False, eventId=to_upload.eventId)

    id: str = str(uuid.uuid4())
    notif = ReleventInfo(
        id=id,
        eventId=to_upload.eventId,
        sourceUserId=to_upload.sourceUserId,
        packageName=to_upload.packageName,
        timestamp=to_upload.timestamp,
        contentHash=to_upload.contentHash,
    )
    session.add(notif)
    session.commit()
    session.refresh(notif)

    try:
        await pool.enqueue_job(
            "detector_pipeline",
            to_upload
            # _job_id=to_upload.eventId,
        )
    except Exception as exc:
        session.delete(notif)
        session.commit()
        logger.error(
            "Failed to enqueue notification analysis: eventId=%s sourceUserId=%s packageName=%s timestamp=%s error=%s",
            to_upload.eventId,
            to_upload.sourceUserId,
            to_upload.packageName,
            to_upload.timestamp,
            type(exc).__name__,
        )
        raise HTTPException(status_code=503, detail="Analysis queue unavailable") from exc

    logger.info(
        "Accepted notification analysis: eventId=%s sourceUserId=%s packageName=%s timestamp=%s",
        to_upload.eventId,
        to_upload.sourceUserId,
        to_upload.packageName,
        to_upload.timestamp,
    )
    return NotificationAccepted(accepted=True, eventId=to_upload.eventId)

@router.get("/rel", response_model=Page[ReleventInfo])
async def get_notifications(session: Session = Depends(get_session)) -> Page[ReleventInfo]:
    return paginate(session=session, query=select(ReleventInfo))


@router.delete("/rel", status_code=204)
async def delete_all_relevant_info(session: Session = Depends(get_session)):
    session.exec(delete(ReleventInfo))
    session.commit()
    return
