import asyncio

from sqlmodel import select, Session
from app.database import get_engine
from app.scheme.malicious_url import MaliciousUrl

def get_closest_distance(query_embedding: list[float]):
    distance_expr = MaliciousUrl.embedding.cosine_distance(query_embedding).label("distance")

    statement = (
        select(distance_expr)
        .order_by(distance_expr)
        .limit(1)
    )
    
    with Session(get_engine()) as session:
        return session.exec(statement).first()

async def get_closest_distance_async(query_embedding: list[float]):
    return await asyncio.to_thread(get_closest_distance, query_embedding)
