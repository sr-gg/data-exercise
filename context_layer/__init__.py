"""A small, local context layer over cloud inventory, Terraform state, Kubernetes
and a service catalog. Answers operational questions with evidence and typed
absence rather than turning incomplete evidence into facts."""

from .ingest import load_inputs, load_manifest
from .resolve import Resolver
from .store import ContextGraph, QueryScope, TenantLeakError

__all__ = [
    "ContextGraph",
    "QueryScope",
    "Resolver",
    "TenantLeakError",
    "load_inputs",
    "load_manifest",
]
