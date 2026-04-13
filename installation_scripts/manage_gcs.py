#!/usr/bin/env python3
"""
GCS Setup and Management

This script helps create and manage the staging bucket required by Vertex AI.
"""

import os
from pathlib import Path
from typing import Annotated, Optional

import typer
from dotenv import load_dotenv
from google.cloud import storage

# Import validation utilities
from installation_scripts.env_validation import is_placeholder_value


app = typer.Typer(
    add_completion=False,
    help="Manage GCS setup for the Google MCP Security Agent.",
)


class GCSManager:
    """Manages GCS setup verification and configuration."""

    def __init__(self, env_file: Path):
        """
        Initialize the GCS manager.

        Args:
            env_file: Path to the environment file.
        """
        self.env_file = env_file
        self.env_vars = self._load_env_vars()
        self.project_id = self.env_vars.get("GCP_PROJECT_ID")
        self.location = self.env_vars.get("GCP_LOCATION")

    def _load_env_vars(self) -> dict[str, str]:
        """Load environment variables from the .env file."""
        if self.env_file.exists():
            load_dotenv(self.env_file, override=True)
        env_vars = dict(os.environ)
        return env_vars

    def bucket_create(self, bucket_name: str, location: Optional[str] = None, storage_class: Optional[str] = "STANDARD"):
        """Create a GCS bucket."""
        if not self.project_id:
            typer.secho("✗ GCP_PROJECT_ID is not set in environment.", fg=typer.colors.RED)
            return False

        location = location or self.location
        if not location:
            typer.secho("✗ GCP_LOCATION is not set in environment and not provided.", fg=typer.colors.RED)
            return False

        # Clean the bucket name
        if bucket_name.startswith("gs://"):
            bucket_name = bucket_name[5:]

        try:
            client = storage.Client(project=self.project_id)
            bucket = client.bucket(bucket_name)

            if bucket.exists():
                typer.secho(f"✓ Bucket {bucket_name} already exists.", fg=typer.colors.GREEN)
                return True

            bucket.storage_class = storage_class
            # Remove regional designation like -a or -b from location
            location = location.split("-")[0] + "-" + location.split("-")[1]

            new_bucket = client.create_bucket(bucket, location=location)
            typer.secho(f"✓ Bucket {new_bucket.name} created successfully in {location}.", fg=typer.colors.GREEN)
            return True

        except Exception as e:
            typer.secho(f"✗ Failed to create bucket: {e}", fg=typer.colors.RED)
            return False


@app.command()
def bucket_create(
    bucket: str = typer.Argument(..., help="The name of the bucket to create (e.g., gs://my-staging-bucket)"),
    location: Annotated[
        Optional[str], typer.Option(help="The location for the bucket. Defaults to GCP_LOCATION.")
    ] = None,
    storage_class: Annotated[
        Optional[str], typer.Option(help="The storage class for the bucket. Defaults to STANDARD.")
    ] = "STANDARD",
    env_file: Annotated[
        Path, typer.Option(help="Path to the environment file.")
    ] = Path(".env"),
) -> None:
    """Create a new GCS bucket."""
    manager = GCSManager(env_file)
    if not manager.bucket_create(bucket, location, storage_class):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
