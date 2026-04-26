def build_ingestion_metadata(source_inventory, schema, profiling):
    return {
        "source_type": source_inventory.get("source_type"),
        "database": source_inventory.get("database"),
        "tables_scanned": list(schema.keys()),
        "num_tables": len(schema),
        "owners": sorted({
            table.get("owner", "unknown")
            for table in source_inventory.get("tables", [])
        }),
        "rows_sampled": {
            table: stats["row_count"]
            for table, stats in profiling.items()
        }
    }
