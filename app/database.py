import os
from sqlmodel import create_engine, SQLModel, Session
from sqlalchemy import delete, text
from arq import create_pool
from arq.connections import RedisSettings

_engine = None


def get_engine():
    global _engine
    if _engine is None:
        url = os.getenv(
            "DATABASE_URL",
            "postgresql+psycopg://nophish:nophish@localhost:5432/nophish",
        )
        _engine = create_engine(url, echo=False)
    return _engine


def init_db():
    engine = get_engine()
    # Enable pgvector extension before creating tables that use the Vector type
    with engine.connect() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
        conn.commit()
    import_table_models()
    SQLModel.metadata.create_all(engine)
    maybe_seed_malicious_urls()


def import_table_models() -> None:
    # SQLModel only creates tables for models imported before create_all().
    from app.scheme import malicious_url, message, notification  # noqa: F401


def env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return int(value)


def env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    return float(value)


def maybe_seed_malicious_urls() -> None:
    if not env_flag("SEED_MALICIOUS_URLS_ON_INIT"):
        return

    from app.scheme.malicious_url import MaliciousUrl
    from eval import seed_malicious_urls

    seed_malicious_urls.load_env_files()

    if env_flag("CLEAR_MALICIOUS_URLS_ON_INIT"):
        with Session(get_engine()) as session:
            session.exec(delete(MaliciousUrl))
            session.commit()

    if env_flag("MALICIOUS_URL_SEED_IF_EMPTY_ONLY", True):
        with Session(get_engine()) as session:
            existing_count = session.exec(
                text("SELECT COUNT(*) FROM maliciousurl")
            ).scalar_one()
        if existing_count:
            return

    seed_limit = env_int("MALICIOUS_URL_SEED_LIMIT", 500)
    limit = None if seed_limit == 0 else seed_limit
    sources = [
        seed_malicious_urls.REPO_ROOT / source
        for source in os.getenv("MALICIOUS_URL_SEED_SOURCES", "").split(os.pathsep)
        if source.strip()
    ] or list(seed_malicious_urls.DEFAULT_SOURCES)

    urls = seed_malicious_urls.collect_urls(
        sources,
        env_flag("MALICIOUS_URL_SEED_INCLUDE_ALL_EVAL_LABELS"),
        limit,
        env_int("MALICIOUS_URL_SEED_FUZZ_VARIANTS", 2),
        env_int("MALICIOUS_URL_SEED_FUZZ_START_INDEX", 0),
        excluded_urls=set(),
        expand_shortlinks=env_flag("MALICIOUS_URL_SEED_EXPAND_SHORTLINKS"),
        shortlink_timeout_seconds=env_float(
            "MALICIOUS_URL_SEED_SHORTLINK_TIMEOUT_SECONDS", 5.0
        ),
        shortlink_max_redirects=env_int("MALICIOUS_URL_SEED_SHORTLINK_MAX_REDIRECTS", 5),
        shortlink_seed_raw=env_flag("MALICIOUS_URL_SEED_SHORTLINK_SEED_RAW", True),
    )
    seed_malicious_urls.seed_urls(
        urls,
        batch_size=env_int("MALICIOUS_URL_SEED_BATCH_SIZE", 50),
        dry_run=False,
    )


def get_session():
    with Session(get_engine()) as session:
        yield session


redis_pool = None
redis_settings = None


async def set_redis_settings(host: str, port: int):
    global redis_settings
    redis_settings = RedisSettings(host, port)


async def get_redis_pool():
    global redis_pool
    global redis_settings
    if redis_pool is None:
        redis_pool = await create_pool(redis_settings)
    return redis_pool


async def close_redis_pool():
    global redis_pool
    if redis_pool:
        await redis_pool.close()
        redis_pool = None
