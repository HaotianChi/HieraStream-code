"""Unversioned publication baseline package."""

__all__ = ["UnversionedWorkflow"]


def __getattr__(name: str):
    if name == "UnversionedWorkflow":
        from experiments.baselines.unversioned.workflow import UnversionedWorkflow

        return UnversionedWorkflow
    raise AttributeError(name)
