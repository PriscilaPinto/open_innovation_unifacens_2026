import os

import psycopg2
from dotenv import load_dotenv


load_dotenv()


def _first_env(*names):
    for name in names:
        value = os.getenv(name)
        if value:
            return value

    return None


def connect_db():
    database_url = _first_env(
        "DATABASE_URL",
        "SUPABASE_DATABASE_URL",
        "SUPABASE_DB_URL",
        "POSTGRES_URL",
        "POSTGRES_PRISMA_URL"
    )

    if database_url:
        return psycopg2.connect(
            database_url,
            sslmode=os.getenv("DB_SSLMODE", "require")
        )

    host = _first_env("DB_HOST", "SUPABASE_DB_HOST")
    database = _first_env("DB_NAME", "SUPABASE_DB_NAME")
    user = _first_env("DB_USER", "SUPABASE_DB_USER")
    password = _first_env("DB_PASSWORD", "SUPABASE_DB_PASSWORD")

    if _first_env("api_key_supa", "SUPABASE_API_KEY") and not password:
        raise RuntimeError(
            "A chave de API do Supabase nao conecta no PostgreSQL. "
            "Configure DATABASE_URL com a connection string do banco, ou "
            "DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD com os dados do Supabase."
        )

    return psycopg2.connect(
        host=host or "localhost",
        port=int(os.getenv("DB_PORT", 5432)),
        database=database or "remediation",
        user=user or "postgres",
        password=password or "postgres",
        sslmode=os.getenv("DB_SSLMODE", "require" if host and host != "localhost" else "prefer")
    )
