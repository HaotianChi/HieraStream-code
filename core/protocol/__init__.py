"""HieraStream protocol package — journal end-to-end workflow."""

from .metadata import build_metadata_object, metadata_bytes

__all__ = ["HieraStreamWorkflow", "build_metadata_object", "metadata_bytes"]


def __getattr__(name: str):
    if name == "HieraStreamWorkflow":
        from .workflow import HieraStreamWorkflow

        return HieraStreamWorkflow
    raise AttributeError(name)
