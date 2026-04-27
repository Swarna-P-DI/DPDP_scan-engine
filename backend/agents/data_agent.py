from sqlalchemy import inspect, text
import logging

from backend.services.scan_evidence import build_schema_analysis
from backend.utils.db import get_engine

logger = logging.getLogger(__name__)


def data_agent(state):
    logger.info("Source Inventory Agent")

    engine = get_engine()
    inspector = inspect(engine)

    schema = {}
    source_inventory = {
        "source_type": engine.dialect.name,
        "database": engine.url.database,
        "tables": []
    }

    table_owners = {}
    try:
        with engine.connect() as connection:
            rows = connection.execute(text("""
                SELECT schemaname, tablename, tableowner
                FROM pg_tables
                WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
            """))
            table_owners = {
                f"{row.schemaname}.{row.tablename}": row.tableowner
                for row in rows
            }
    except Exception:
        table_owners = {}

    schema_names = [
        s for s in inspector.get_schema_names()
        if s not in ("information_schema", "pg_catalog")
    ] or [None]

    for schema_name in schema_names:
        for table in inspector.get_table_names(schema=schema_name)[:50]:
            qualified_name = f"{schema_name}.{table}" if schema_name else table
            columns = inspector.get_columns(table, schema=schema_name)
            primary_key = inspector.get_pk_constraint(table, schema=schema_name) or {}
            foreign_keys = inspector.get_foreign_keys(table, schema=schema_name) or []
            indexes = inspector.get_indexes(table, schema=schema_name) or []

            schema[qualified_name] = [col["name"] for col in columns]
            source_inventory["tables"].append({
                "schema": schema_name,
                "table": table,
                "qualified_name": qualified_name,
                "owner": table_owners.get(qualified_name, "unknown"),
                "dataset_owner": table_owners.get(qualified_name, "unknown"),
                "data_steward": "Data Engineering / Data Steward",
                "ownership_status": (
                    "missing"
                    if table_owners.get(qualified_name, "unknown") in (None, "", "unknown", "postgres")
                    else "resolved"
                ),
                "columns": [
                    {
                        "name": col["name"],
                        "type": str(col.get("type")),
                        "nullable": bool(col.get("nullable", True)),
                        "default": str(col.get("default")) if col.get("default") is not None else None,
                        "primary_key": col["name"] in primary_key.get("constrained_columns", [])
                    }
                    for col in columns
                ],
                "primary_key": primary_key.get("constrained_columns", []),
                "foreign_keys": [
                    {
                        "columns": fk.get("constrained_columns", []),
                        "referred_schema": fk.get("referred_schema"),
                        "referred_table": fk.get("referred_table"),
                        "referred_columns": fk.get("referred_columns", [])
                    }
                    for fk in foreign_keys
                ],
                "indexes": [
                    {
                        "name": idx.get("name"),
                        "columns": idx.get("column_names", []),
                        "unique": bool(idx.get("unique", False))
                    }
                    for idx in indexes
                ]
            })

    return {
        "schema": schema,
        "source_inventory": source_inventory,
        "schema_analysis": build_schema_analysis(source_inventory)
    }
