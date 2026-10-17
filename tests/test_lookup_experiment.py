import asyncio
import csv

import pytest

from overlay_node.experiment import run_lookup_experiment


def test_lookup_experiment_records_absent_multihop_targets(tmp_path):
    async def scenario():
        output = tmp_path / "lookup-results.csv"
        summary = await run_lookup_experiment(
            count=4,
            output_path=output,
            seed=12345,
        )

        assert summary["search_count"] == 4
        assert int(summary["multihop_count"]) >= 1
        assert summary["found_count"] == 0
        assert summary["error_count"] == 0
        assert output.exists()

        with output.open("r", encoding="utf-8-sig", newline="") as csv_file:
            rows = list(csv.DictReader(csv_file))

        assert len(rows) == 4
        assert {row["initiator_initial_table_size"] for row in rows} == {"0"}
        assert all(int(row["rpc_count"]) >= 1 for row in rows)
        assert all(row["target_found"] == "False" for row in rows)
        assert all(row["bootstrap_node_id"] in row["queried_node_ids"] for row in rows)
        assert all(row["errors"] == "" for row in rows)

    asyncio.run(scenario())


def test_lookup_experiment_rejects_zero_search_count(tmp_path):
    async def scenario():
        with pytest.raises(ValueError, match="не меньше 1"):
            await run_lookup_experiment(count=0, output_path=tmp_path / "empty.csv")

    asyncio.run(scenario())
