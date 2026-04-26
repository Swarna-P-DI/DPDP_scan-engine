def compute_diff(current, previous):
    if not previous:
        return {"message": "No previous run"}

    changes = {}

    # Example: schema diff
    curr_tables = set(current["schema"].keys())
    prev_tables = set(previous["data"]["schema"].keys())

    changes["new_tables"] = list(curr_tables - prev_tables)
    changes["removed_tables"] = list(prev_tables - curr_tables)

    # Example: score change
    changes["score_change"] = {
        "previous": previous["data"]["scores"]["final_score"],
        "current": current["scores"]["final_score"]
    }

    return changes