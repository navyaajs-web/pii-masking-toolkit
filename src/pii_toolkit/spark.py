"""SparkSession factory tuned for a laptop or CI runner rather than a cluster."""

from __future__ import annotations

import os
import sys

from pyspark.sql import SparkSession


def get_spark(app_name: str = "pii-toolkit") -> SparkSession:
    # Python workers must use this interpreter (the venv that has pii_toolkit installed),
    # not whatever `python3` happens to be first on PATH.
    os.environ.setdefault("PYSPARK_PYTHON", sys.executable)
    spark = (
        SparkSession.builder.appName(app_name)
        .master("local[2]")
        # Small data: the default 200 shuffle partitions only adds scheduling overhead.
        .config("spark.sql.shuffle.partitions", "4")
        .config("spark.ui.enabled", "false")
        .config("spark.ui.showConsoleProgress", "false")
        .config("spark.sql.session.timeZone", "UTC")
        # Plain row-at-a-time UDFs: avoids a pandas/pyarrow dependency for a few crypto calls.
        .config("spark.sql.execution.pythonUDF.arrow.enabled", "false")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("ERROR")
    return spark
