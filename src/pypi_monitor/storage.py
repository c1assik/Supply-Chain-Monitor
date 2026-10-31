"""S3-compatible artifact storage."""

from pathlib import Path

import boto3
from botocore.config import Config


class ArtifactStorage:
    """Synchronous on purpose: callers run it in a thread, like analyzers."""

    def __init__(self, endpoint: str, access_key: str, secret_key: str, bucket: str) -> None:
        self._bucket = bucket
        self._s3 = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name="us-east-1",
            config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 3}),
        )

    def put(self, path: Path, key: str) -> None:
        self._s3.upload_file(str(path), self._bucket, key)

    def get(self, key: str, path: Path) -> None:
        self._s3.download_file(self._bucket, key, str(path))
