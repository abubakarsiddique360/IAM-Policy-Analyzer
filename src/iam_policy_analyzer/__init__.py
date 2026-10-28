"""IAM-Policy-Analyzer: evaluate and review IAM policy documents."""

from .evaluate import Decision, Request, evaluate
from .policy import Policy, PolicyError, load_policy
from .review import Finding, Review, review

__all__ = [
    "Decision",
    "Finding",
    "Policy",
    "PolicyError",
    "Request",
    "Review",
    "evaluate",
    "load_policy",
    "review",
]

__version__ = "1.0.0"
