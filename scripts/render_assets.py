"""Regenerate README assets from the example policy.

Usage:  python scripts/render_assets.py
Writes: docs/review.json, docs/images/iam-review.png, docs/images/decision-matrix.svg
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from PIL import Image, ImageDraw, ImageFont  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from iam_policy_analyzer.evaluate import Request, evaluate  # noqa: E402
from iam_policy_analyzer.policy import load_policy  # noqa: E402
from iam_policy_analyzer.report import render_review  # noqa: E402
from iam_policy_analyzer.review import SEVERITY_ORDER, review  # noqa: E402

BG = "#0d1117"
CHROME = "#161b22"
FG = "#e6edf3"
MUTED = "#8b949e"
SEVERITY_COLORS = {
    "critical": "#f85149",
    "high": "#db6d28",
    "medium": "#d29922",
    "low": "#2f81f7",
}

ACTIONS = (
    "s3:GetObject",
    "s3:DeleteObject",
    "iam:CreateUser",
    "iam:PassRole",
    "kms:Decrypt",
    "ec2:TerminateInstances",
)
RESOURCES = (
    ("build-artifacts", "arn:aws:s3:::build-artifacts/app.zip"),
    ("production-logs", "arn:aws:s3:::production-logs/app.log"),
    ("deploy-role", "arn:aws:iam::111122223333:role/deploy-role"),
    ("demo-key", "arn:aws:kms:eu-west-1:111122223333:key/demo-key"),
    ("instance", "arn:aws:ec2:eu-west-1:111122223333:instance/i-0abc"),
)
CONTEXT = {
    "aws:SourceIp": "203.0.113.9",
    "aws:PrincipalOrgID": "o-example",
    "iam:PassedToService": "ecs-tasks.amazonaws.com",
}


def load_font(size: int) -> ImageFont.FreeTypeFont:
    for name in ("consola.ttf", "cour.ttf", "DejaVuSansMono.ttf"):
        candidate = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts" / name
        if candidate.exists():
            return ImageFont.truetype(str(candidate), size)
    return ImageFont.load_default()


def render_terminal(text: str, out_path: Path, title: str) -> None:
    font = load_font(14)
    lines = text.expandtabs(4).splitlines() or [""]
    probe = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    char_width = probe.textlength("M", font=font)
    line_height = 21
    pad = 24
    width = int(max(len(line) for line in lines) * char_width) + pad * 2
    height = pad * 2 + len(lines) * line_height + 44
    image = Image.new("RGB", (max(width, 800), height), BG)
    draw = ImageDraw.Draw(image)
    draw.rectangle([0, 0, image.width, 34], fill=CHROME)
    for index, color in enumerate(("#ff5f56", "#ffbd2e", "#27c93f")):
        draw.ellipse([16 + index * 22, 10, 28 + index * 22, 22], fill=color)
    draw.text((92, 9), title, font=load_font(12), fill=MUTED)

    for row, line in enumerate(lines):
        color = FG
        stripped = line.strip()
        if row == 0:
            color = "#79c0ff"
        elif stripped in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            color = SEVERITY_COLORS[stripped.lower()]
        elif "fix:" in line:
            color = "#3fb950"
        elif stripped.startswith("risk"):
            color = "#d29922"
        draw.text((pad, 48 + row * line_height), line, font=font, fill=color)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(out_path)


def render_charts(policy, result, hardened, out_path: Path) -> None:
    fig, (ax_sev, ax_now, ax_fixed) = plt.subplots(
        1, 3, figsize=(15.6, 4.6), gridspec_kw={"width_ratios": [0.62, 1.2, 1.2]}
    )
    fig.patch.set_facecolor("#ffffff")

    severities = [name for name in SEVERITY_ORDER if result.counts.get(name)]
    ax_sev.bar(severities, [result.counts[name] for name in severities],
               color=[SEVERITY_COLORS[name] for name in severities])
    for index, name in enumerate(severities):
        ax_sev.text(index, result.counts[name] + 0.05, str(result.counts[name]),
                    ha="center", fontsize=9, color="#24292f")
    ax_sev.set_ylabel("findings")
    ax_sev.set_title(f"Risk {result.risk} points (grade {result.grade})", fontsize=11,
                     loc="left")
    ax_sev.set_ylim(0, max(result.counts.values()) + 1.5)
    ax_sev.grid(axis="y", linestyle=":", alpha=0.45)
    for spine in ("top", "right"):
        ax_sev.spines[spine].set_visible(False)

    for axis, document, title in (
        (ax_now, policy, "As written: one statement allows everything"),
        (ax_fixed, hardened, "Scoped: only the listed paths"),
    ):
        grid = [
            [
                evaluate(document, Request(action, arn, CONTEXT)).allowed
                for _label, arn in RESOURCES
            ]
            for action in ACTIONS
        ]
        image = [[1 if allowed else 0 for allowed in row] for row in grid]
        axis.imshow(image, cmap=matplotlib.colors.ListedColormap(["#f2b8b5", "#a7e0b0"]),
                    vmin=0, vmax=1, aspect="auto")
        axis.set_xticks(range(len(RESOURCES)))
        axis.set_xticklabels([label for label, _ in RESOURCES], rotation=25, ha="right",
                             fontsize=7)
        axis.set_yticks(range(len(ACTIONS)))
        axis.set_yticklabels(ACTIONS, fontsize=7)
        axis.set_title(title, fontsize=10, loc="left")
        axis.set_xticks([x - 0.5 for x in range(1, len(RESOURCES))], minor=True)
        axis.set_yticks([y - 0.5 for y in range(1, len(ACTIONS))], minor=True)
        axis.grid(which="minor", color="white", linewidth=1.5)
        axis.tick_params(which="minor", length=0)
        for row_index, row in enumerate(grid):
            for column_index, allowed in enumerate(row):
                axis.text(column_index, row_index, "allow" if allowed else "deny",
                          ha="center", va="center", fontsize=6.5,
                          color="#14532d" if allowed else "#7f1d1d")

    fig.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, format=out_path.suffix.lstrip(".") or "svg", transparent=False)
    plt.close(fig)


def main() -> int:
    images = ROOT / "docs" / "images"
    images.mkdir(parents=True, exist_ok=True)
    policy = load_policy(ROOT / "examples" / "policy.json")
    hardened = load_policy(ROOT / "examples" / "policy-hardened.json")
    result = review(policy)
    hardened_result = review(hardened)

    (ROOT / "docs" / "review.json").write_text(
        json.dumps({"as_written": result.as_dict(), "hardened": hardened_result.as_dict()},
                   indent=2),
        encoding="utf-8",
    )
    header = "iam-analyze review --policy examples/policy.json\n\n"
    render_terminal(header + render_review(result), images / "iam-review.png",
                    "iam-analyze  -  what this policy actually grants")
    render_charts(policy, result, hardened, images / "decision-matrix.svg")
    print(f"as-written risk={result.risk} grade={result.grade} counts={result.counts}")
    print(f"hardened   risk={hardened_result.risk} grade={hardened_result.grade} "
          f"counts={hardened_result.counts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
