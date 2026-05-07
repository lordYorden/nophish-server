from sqlmodel import SQLModel, Field
from pgvector.sqlalchemy import Vector
from sqlalchemy import Column
from typing import Optional

EMBEDDING_DIM = 384  # all-MiniLM-L6-v2 output dimension


class MaliciousUrl(SQLModel, table=True):
    __tablename__ = "maliciousurl"

    id: Optional[int] = Field(default=None, primary_key=True)
    url: str = Field(index=True)
    embedding: list[float] = Field(sa_type=Vector(EMBEDDING_DIM))
