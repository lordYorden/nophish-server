import asyncio
import logging
import os
from arq.connections import RedisSettings
from sqlmodel import Session, select
from sqlalchemy import func, update
from llm.openr import check_message_with_llm, get_url_embedding_async
from fcm.firebase import send_fcm_message
from app.scheme.notification import NotificationSubmission, ReleventInfo
from app.scheme.malicious_url import MaliciousUrl
from app.database import get_engine
from fcm.firebase import initialize_firebase
from pgvec.distance import get_closest_distance_async

CONFIDENCE_THRESHOLD = 0.7
SIMILARITY_THRESHOLD = 0.15 
logger = logging.getLogger(__name__)

initialize_firebase()


def get_existing_malicious_url(session: Session, url: str) -> MaliciousUrl | None:
    return session.exec(select(MaliciousUrl).where(MaliciousUrl.url == url)).first()


def mark_event_alerted(event_id: str) -> bool:
    with Session(get_engine()) as session:
        result = session.exec(
            update(ReleventInfo)
            .where(ReleventInfo.eventId == event_id)
            .where(ReleventInfo.alerted.is_(False))
            .values(alerted=True)
        )
        session.commit()
        return result.rowcount == 1


async def run_llm_and_decide(notif: NotificationSubmission) -> bool:
    is_phish, confidence = await check_message_with_llm(notif.body, notif.packageName)
    
    logger.info(
        "LLM decision: eventId=%s timestamp=%s verdict=%s confidence=%s",
        notif.eventId,
        notif.timestamp,
        "malicious" if is_phish else "benign",
        confidence,
    )
    return is_phish


async def module_b(notif: NotificationSubmission) -> bool:
    # await asyncio.sleep(2)
    return True


async def module_url_embedding(notif: NotificationSubmission) -> bool:
    """Check if any URL in the message is similar to a known malicious URL via pgvector cosine distance."""
    if not notif.urls:
        return False

    with Session(get_engine()) as session:
        count = session.exec(select(func.count(MaliciousUrl.id))).one()
        if count == 0:
            return True #TOOD: change to false after testing

        for url in notif.urls:
            if get_existing_malicious_url(session, url):
                logger.info(
                    "URL exactly matched a known malicious URL: eventId=%s timestamp=%s",
                    notif.eventId,
                    notif.timestamp,
                )
                return True

            embedding = await get_url_embedding_async(url)

            dist = await get_closest_distance_async(embedding)

            if dist < SIMILARITY_THRESHOLD:
                logger.info(
                    "URL matched a known malicious URL: eventId=%s timestamp=%s distance=%.4f",
                    notif.eventId,
                    notif.timestamp,
                    dist,
                )
                return True

            logger.info(
                "URL did not match known malicious URLs: eventId=%s timestamp=%s distance=%.4f",
                notif.eventId,
                notif.timestamp,
                dist,
            )

    return False


async def aggregate_and_act(results, notif: NotificationSubmission):
    phishing_votes = sum(1 for result in results if result)
    
    logger.info(
        "Aggregated notification verdict: eventId=%s timestamp=%s verdict=%s votes=%s/3",
        notif.eventId,
        notif.timestamp,
        "malicious" if phishing_votes >= 2 else "benign",
        phishing_votes,
    )

    if phishing_votes >= 2:
        if not mark_event_alerted(notif.eventId):
            logger.info(
                "Skipping duplicate malicious alert: eventId=%s timestamp=%s",
                notif.eventId,
                notif.timestamp,
            )
            return

        send_fcm_message(
            topic="test_topic",
            title="Phishing Alert",
            body="A notification has been flagged as phishing.",
            data={"data": notif.model_dump_json(exclude_none=True)},
        )

        if notif.urls:
            with Session(get_engine()) as session:
                for url in notif.urls:
                    if get_existing_malicious_url(session, url):
                        continue

                    embedding = await get_url_embedding_async(url)
                    session.add(MaliciousUrl(url=url, embedding=embedding))
                session.commit()
            logger.info(
                "Processed malicious URLs for indexing: eventId=%s timestamp=%s count=%s",
                notif.eventId,
                notif.timestamp,
                len(notif.urls),
            )


async def detector_pipeline(ctx, notif: NotificationSubmission):
    
    # Run all three modules simultaneously
    results = await asyncio.gather(
        run_llm_and_decide(notif),
        module_b(notif),
        module_url_embedding(notif),
    )

    logger.info(
        "Processing notification analysis job: jobId=%s eventId=%s timestamp=%s",
        ctx["job_id"],
        notif.eventId,
        notif.timestamp,
    )

    await aggregate_and_act(results, notif)


class WorkerSettings:
    functions = [detector_pipeline]
    redis_settings = RedisSettings(host=os.getenv("REDIS_HOST", "localhost"))
