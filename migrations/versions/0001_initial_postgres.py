"""Initial Postgres migration

Revision ID: 0001_initial_postgres
Revises: 
Create Date: 2026-03-28

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel
from pgvector.sqlalchemy import Vector

# revision identifiers, used by Alembic.
revision: str = '0001_initial_postgres'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

EMBEDDING_DIM = 384  # all-MiniLM-L6-v2


def upgrade() -> None:
    # Enable the pgvector extension
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    # smsmessage table
    op.create_table(
        'smsmessage',
        sa.Column('phone_number', sqlmodel.AutoString(), nullable=False),
        sa.Column('body', sqlmodel.AutoString(), nullable=True),
        sa.Column('timestamp', sa.Integer(), nullable=True),
        sa.Column('id', sqlmodel.AutoString(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )

    # notification table
    op.create_table(
        'notification',
        sa.Column('title', sqlmodel.AutoString(), nullable=False),
        sa.Column('extraTitle', sqlmodel.AutoString(), nullable=True),
        sa.Column('isGroup', sa.Boolean(), nullable=True),
        sa.Column('body', sqlmodel.AutoString(), nullable=True),
        sa.Column('timestamp', sa.Integer(), nullable=True),
        sa.Column('packageName', sqlmodel.AutoString(), nullable=True),
        sa.Column('id', sqlmodel.AutoString(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )

    # releventinfo table
    op.create_table(
        'releventinfo',
        sa.Column('body', sqlmodel.AutoString(), nullable=True),
        sa.Column('packageName', sqlmodel.AutoString(), nullable=True),
        sa.Column('hash', sqlmodel.AutoString(), nullable=True),
        sa.Column('urls', sa.JSON(), nullable=True),
        sa.Column('id', sqlmodel.AutoString(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )

    # maliciousurl table with vector embedding column
    op.create_table(
        'maliciousurl',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('url', sqlmodel.AutoString(), nullable=False),
        sa.Column('embedding', Vector(EMBEDDING_DIM), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_maliciousurl_url'), 'maliciousurl', ['url'])

    # HNSW index for fast cosine similarity search on embeddings
    op.execute(
        "CREATE INDEX maliciousurl_embedding_hnsw_idx "
        "ON maliciousurl USING hnsw (embedding vector_cosine_ops)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS maliciousurl_embedding_hnsw_idx")
    op.drop_index(op.f('ix_maliciousurl_url'), table_name='maliciousurl')
    op.drop_table('maliciousurl')
    op.drop_table('releventinfo')
    op.drop_table('notification')
    op.drop_table('smsmessage')
    op.execute("DROP EXTENSION IF EXISTS vector")
