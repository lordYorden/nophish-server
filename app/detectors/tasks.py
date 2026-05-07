import asyncio
import os
from arq.connections import RedisSettings
from sqlmodel import Session, select
from sqlalchemy import func
from llm.openr import check_message_with_llm, get_url_embedding
from fcm.firebase import send_fcm_message
from app.scheme.notification import ReleventInfo
from app.scheme.malicious_url import MaliciousUrl
from app.database import get_engine
from fcm.firebase import initialize_firebase
from pgvec.distance import get_closest_distance

CONFIDENCE_THRESHOLD = 0.7
SIMILARITY_THRESHOLD = 0.15 

initialize_firebase()


async def run_llm_and_decide(notif: ReleventInfo) -> bool:
    is_phish, confidence = check_message_with_llm(notif.body)
    print(f"LLM decision for notification {notif.id}: is_phish={is_phish}, confidence={confidence}")
    return is_phish


async def module_b(notif: ReleventInfo) -> bool:
    # await asyncio.sleep(2)
    return True


async def module_url_embedding(notif: ReleventInfo) -> bool:
    """Check if any URL in the message is similar to a known malicious URL via pgvector cosine distance."""
    if not notif.urls:
        return False

    with Session(get_engine()) as session:
        count = session.exec(select(func.count(MaliciousUrl.id))).one()
        if count == 0:
            return True #TOOD: change to false after testing

        for url in notif.urls:
            embedding = get_url_embedding(url)

            dist = get_closest_distance(embedding)

            if dist < SIMILARITY_THRESHOLD:
                print(f"URL '{url}' matched a known malicious URL (distance={dist:.4f})")
                return True

            print(f"URL '{url}' did not match any known malicious URL (distance={dist:.4f})")

    return False


async def aggregate_and_act(results, notif: ReleventInfo):
    phishing_votes = sum(1 for result in results if result)
    print(f"Phishing votes: {phishing_votes}/3 for notification {notif.id}")

    if phishing_votes >= 2:
        print("Notification flagged as phishing by majority. Indexing URLs and alerting.")

        send_fcm_message(
            topic="test_topic",
            title="Phishing Alert",
            body="A notification has been flagged as phishing.",
            data={"data" : notif.model_dump_json(include={"urls", "packageName", "body"})}
        )

        if notif.urls:
            with Session(get_engine()) as session:
                for url in notif.urls:
                    embedding = get_url_embedding(url)
                    session.add(MaliciousUrl(url=url, embedding=embedding))
                session.commit()
            print(f"Indexed {len(notif.urls)} malicious URL(s) in Postgres.")


async def detector_pipeline(ctx, data: ReleventInfo):
    # Run all three modules simultaneously
    results = await asyncio.gather(
        run_llm_and_decide(data),
        module_b(data),
        module_url_embedding(data),
    )

    print(f"Processing job {ctx['job_id']} for notification.")

    await aggregate_and_act(results, notif=data)


class WorkerSettings:
    functions = [detector_pipeline]
    redis_settings = RedisSettings(host=os.getenv("REDIS_HOST", "localhost"))