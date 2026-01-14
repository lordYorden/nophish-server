import asyncio
import os
from arq.connections import RedisSettings
from llm.openr import check_message_with_llm
from fcm.firebase import send_fcm_message
from app.scheme.notification import ReleventInfo
from fcm.firebase import initialize_firebase

CONFIDENCE_THRESHOLD = 0.7
initialize_firebase()

async def run_llm_and_decide(notif: ReleventInfo):
    is_phish, confidence = check_message_with_llm(notif.body)

    print(f"LLM decision for notification {notif.id}: is_phish={is_phish}, confidence={confidence}")
    return is_phish

async def module_b(notif: ReleventInfo):
    await asyncio.sleep(2)
    return False

async def module_c(notif: ReleventInfo):
    await asyncio.sleep(2)
    return True

async def aggregate_and_act(results, notif: ReleventInfo):
    # at least two module flagged as phishing
    phishing_votes = sum(1 for result in results if result)
    if phishing_votes >= 2:
        print("Notification flagged as phishing by majority. Taking action.")
        send_fcm_message(
            topic="test_topic",
            title="Phishing Alert",
            body="A notification has been flagged as phishing.",
            data={"test": notif.packageName}
        )

async def detector_pipeline(ctx, data: ReleventInfo):
    # Run simultaneously
    results = await asyncio.gather(
        run_llm_and_decide(data), 
        module_b(data), 
        module_c(data)
    )

    print(f"Processing job {ctx['job_id']} for notification.")
    
    await aggregate_and_act(results, notif=data)

class WorkerSettings:
    functions = [detector_pipeline]
    redis_settings = RedisSettings(host=os.getenv("REDIS_HOST", "localhost"))