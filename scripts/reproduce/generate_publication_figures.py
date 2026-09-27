#!/usr/bin/env python3
"""Generate publication figures under ``results/{figures,data,tables}/``."""

from __future__ import annotations

import csv
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.transforms as mtransforms
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Rectangle
from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
# Minimal public layout: results/{figures,data,tables}
OUT = ROOT / "results"
FIG = OUT / "_panels"
ASSETS = OUT
PIC = OUT / "figures"
TAB = OUT / "tables"
DATA = OUT / "data"

# IEEE-ish style
plt.rcParams.update(
    {
        "font.family": "Times New Roman",
        "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        "mathtext.fontset": "stix",
        "mathtext.rm": "Times New Roman",
        "mathtext.it": "Times New Roman",
        "mathtext.bf": "Times New Roman",
        "font.size": 9,
        "axes.labelsize": 11,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "legend.fontsize": 9.5,
        "axes.linewidth": 0.8,
        "lines.linewidth": 1.4,
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "figure.dpi": 150,
        "savefig.dpi": 300,
        # Tight-crop whitespace; then uniformize_tight_panel_groups() pads to equal size.
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.03,
    }
)

SCHEME_STYLE = {
    "HieraStream": {"marker": "o", "linestyle": "-", "color": "#1f77b4"},
    "Droplet": {"marker": "s", "linestyle": "-", "color": "#ff7f0e"},
    "TimeCrypt": {"marker": "^", "linestyle": "-", "color": "#2ca02c"},
    "CP-ABE": {"marker": "s", "linestyle": "-", "color": "#ff7f0e"},
    "PASH": {"marker": "^", "linestyle": "-", "color": "#2ca02c"},
    "MASS": {"marker": "D", "linestyle": "-", "color": "#d62728"},
    "Historical-update": {"marker": "v", "linestyle": "-", "color": "#9467bd"},
    "Unversioned": {"marker": "x", "linestyle": "-", "color": "#8c564b"},
    "mean": {"marker": "o", "linestyle": "-", "color": "#1f77b4"},
    "p95": {"marker": "s", "linestyle": "-", "color": "#d62728"},
    "throughput": {"marker": "o", "linestyle": "-", "color": "#1f77b4"},
    "mean_latency": {"marker": "s", "linestyle": "-", "color": "#ff7f0e"},
    "p95_latency": {"marker": "^", "linestyle": "-", "color": "#2ca02c"},
    "ideal": {"marker": None, "linestyle": ":", "color": "#7f7f7f"},  # baseline / offered reference
    "HS_stale": {"marker": "o", "linestyle": "-", "color": "#1f77b4"},
    "UV_stale": {"marker": "s", "linestyle": "-", "color": "#d62728"},
    "HS_retry": {"marker": "^", "linestyle": "-", "color": "#2ca02c"},
    "metadata": {"marker": "o", "linestyle": "-", "color": "#1f77b4"},
    "pub_lat": {"marker": "s", "linestyle": "-", "color": "#d62728"},
}

# Fixed plot rectangle (x/y axes box) in inches; outer figure grows for tick/axis labels.
# Final panel files are tight-cropped, then padded per figN group to identical size.
AXES_SIZE_IN = (2.60, 1.85)
_MARGIN_L, _MARGIN_B, _MARGIN_T = 0.85, 0.70, 0.22
_MARGIN_R = 0.28
_MARGIN_R_TWIN = 0.85

# Shared series styling
BAR_EDGE = {"edgecolor": "black", "linewidth": 0.4}
MARKER_SIZE = 2.2
MARKER_SIZE_INSET = 1.8
# Fig.4 Mean/P95 bars: soft low-contrast orange/green
FIG4_MEAN_COLOR = "#e8ab76"
FIG4_P95_COLOR = "#5b925b"


MANIFEST_ROWS: List[Dict[str, Any]] = []

PLOT_SCRIPT = "scripts/reproduce/generate_publication_figures.py"

# Canonical experiment panels: copy fig* → semantic names (pdf + png).
# Packaged filenames use manuscript figure prefixes (e.g. fig4a-...).
FIGURE_COPY_SPEC: List[Dict[str, str]] = [
    {
        "stem": "fig4a",
        "semantic": "fig4a-attr_gateway_partial",
        "experiment": "E1",
        "run": "20260912T041730Z-b8c2c19a",
        "data_csv": "results/data/attr_crypto_cost.csv",
    },
    {
        "stem": "fig4b",
        "semantic": "fig4b-attr_user_final",
        "experiment": "E1",
        "run": "20260912T041730Z-b8c2c19a",
        "data_csv": "results/data/attr_crypto_cost.csv",
    },
    {
        "stem": "fig4c",
        "semantic": "fig4c-attr_outsourced_encryption",
        "experiment": "E1",
        "run": "20260912T041730Z-b8c2c19a",
        "data_csv": "results/data/attr_crypto_cost.csv",
    },
    {
        "stem": "fig4d",
        "semantic": "fig4d-attr_outsourced_decryption",
        "experiment": "E1",
        "run": "20260912T041730Z-b8c2c19a",
        "data_csv": "results/data/attr_crypto_cost.csv",
    },
    {
        "stem": "fig5a",
        "semantic": "fig5a-role_target_scaling",
        "experiment": "E2",
        "run": "20260912T042011Z-506190d0",
        "data_csv": "results/data/role_cost.csv",
    },
    {
        "stem": "fig5b",
        "semantic": "fig5b-role_path_scaling",
        "experiment": "E2",
        "run": "20260912T042011Z-506190d0",
        "data_csv": "results/data/role_cost.csv",
    },
    {
        "stem": "fig6a",
        "semantic": "fig6a-fabric_resource_management",
        "experiment": "E3",
        "run": "composite:E3_low_mid+high_load",
        "data_csv": "results/data/fabric_performance.csv",
    },
    {
        "stem": "fig6b",
        "semantic": "fig6b-fabric_policy_management",
        "experiment": "E3",
        "run": "composite:E3_low_mid+high_load",
        "data_csv": "results/data/fabric_performance.csv",
    },
    {
        "stem": "fig6c",
        "semantic": "fig6c-fabric_commit_segment",
        "experiment": "E3",
        "run": "composite:E3_low_mid+high_load",
        "data_csv": "results/data/fabric_performance.csv",
    },
    {
        "stem": "fig6d",
        "semantic": "fig6d-fabric_update_authorization",
        "experiment": "E3",
        "run": "composite:E3_low_mid+high_load",
        "data_csv": "results/data/fabric_performance.csv",
    },
    {
        "stem": "fig7a",
        "semantic": "fig7a-authorization_consistency",
        "experiment": "E4_paired",
        "run": "20260927T172314Z-642f8d58",
        "data_csv": "results/data/authorization_consistency.csv",
    },
    {
        "stem": "fig7b",
        "semantic": "fig7b-longitudinal_replay_scalability",
        "experiment": "E6",
        "run": "20260912T065259Z-eba2f6a4",
        "data_csv": "results/data/longitudinal_scalability.csv",
    },
    {
        "stem": "fig7c",
        "semantic": "fig7c-segment_granularity",
        "experiment": "E7",
        "run": "",
        "data_csv": "results/data/segment_granularity.csv",
    },
    {
        "stem": "fig7d",
        "semantic": "fig7d-revocation_history_scaling",
        "experiment": "E8",
        "run": "20260912T042510Z-33808d5d",
        "data_csv": "results/data/revocation_history.csv",
    },
    {
        "stem": "fig8a",
        "semantic": "fig8a-baseline_protection_comparison",
        "experiment": "E10B",
        "run": "20260913T154655Z-a5e3d0d8",
        "data_csv": "results/data/baseline_comparison.csv",
    },
    {
        "stem": "fig8b",
        "semantic": "fig8b-baseline_recovery_comparison",
        "experiment": "E10B",
        "run": "20260913T154655Z-a5e3d0d8",
        "data_csv": "results/data/baseline_comparison.csv",
    },
    {
        "stem": "fig9a",
        "semantic": "system_baseline_latency_ecdf",
        "experiment": "system_baselines",
        "run": "20260919T181630Z",
        "data_csv": "results/data/system_baseline_comparison.csv",
    },
    {
        "stem": "fig9b",
        "semantic": "system_baseline_size_scaling",
        "experiment": "system_baselines",
        "run": "20260919T181630Z",
        "data_csv": "results/data/system_baseline_comparison.csv",
    },
    {
        "stem": "fig9c",
        "semantic": "system_baseline_throughput",
        "experiment": "system_baselines",
        "run": "20260919T181630Z",
        "data_csv": "results/data/system_baseline_comparison.csv",
    },
]

TRACE: List[Dict[str, Any]] = []


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


sha256 = sha256_file  # alias used by manuscript packaging


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_csv(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows: List[Dict[str, Any]], fields: Sequence[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields = list(fields or rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})


def save_panel(fig: plt.Figure, stem: str, *, processed_source: str, raw_source: str, config: str, run_id: str) -> None:
    """Save intermediate panels under results/_panels/ (tight crop)."""
    FIG.mkdir(parents=True, exist_ok=True)
    pdf = FIG / f"{stem}.pdf"
    png = FIG / f"{stem}.png"
    save_kw = dict(bbox_inches="tight", pad_inches=0.03)
    fig.savefig(pdf, **save_kw)
    fig.savefig(png, **save_kw)
    plt.close(fig)
    MANIFEST_ROWS.append(
        {
            "figure": stem.rstrip("abcd") if stem[-1].isdigit() is False and len(stem) > 3 else stem[:4],
            "panel": stem,
            "final_pdf": str(pdf.relative_to(OUT)),
            "final_png": str(png.relative_to(OUT)),
            "processed_source": processed_source,
            "canonical_raw_source": raw_source,
            "config": config,
            "run_id": run_id,
            "sha256_pdf": sha256_file(pdf),
        }
    )


def categorical_axis(ax, labels: Sequence[Any]) -> List[int]:
    xs = list(range(len(labels)))
    ax.set_xticks(xs)
    ax.set_xticklabels([str(v) for v in labels])
    return xs


def style_ax(ax) -> None:
    ax.grid(False)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)


def new_panel(*, twin: bool = False):
    """Fixed x–y axes rectangle; margins leave room for ticks/labels."""
    ax_w, ax_h = AXES_SIZE_IN
    right = _MARGIN_R_TWIN if twin else _MARGIN_R
    fig_w = _MARGIN_L + ax_w + right
    fig_h = _MARGIN_B + ax_h + _MARGIN_T
    fig = plt.figure(figsize=(fig_w, fig_h))
    ax = fig.add_axes([_MARGIN_L / fig_w, _MARGIN_B / fig_h, ax_w / fig_w, ax_h / fig_h])
    if twin:
        return fig, ax, ax.twinx()
    return fig, ax


def _panel_group_key(stem: str) -> str:
    """fig4a → fig4, fig8b → fig8."""
    import re

    m = re.match(r"(fig\d+)", stem)
    return m.group(1) if m else stem


def _pad_png_centered(path: Path, target_w: int, target_h: int) -> None:
    im = Image.open(path).convert("RGBA")
    if im.size == (target_w, target_h):
        im.convert("RGB").save(path)
        return
    canvas = Image.new("RGB", (target_w, target_h), (255, 255, 255))
    x = (target_w - im.width) // 2
    y = (target_h - im.height) // 2
    canvas.paste(im, (x, y), im)
    canvas.save(path)


def _pad_pdf_centered(path: Path, target_w: float, target_h: float) -> None:
    import fitz

    src = fitz.open(path)
    page = src[0]
    ow, oh = float(page.rect.width), float(page.rect.height)
    if abs(ow - target_w) < 0.05 and abs(oh - target_h) < 0.05:
        src.close()
        return
    dst = fitz.open()
    new_page = dst.new_page(width=target_w, height=target_h)
    x0 = (target_w - ow) / 2.0
    y0 = (target_h - oh) / 2.0
    new_page.show_pdf_page(fitz.Rect(x0, y0, x0 + ow, y0 + oh), src, 0)
    tmp = path.with_suffix(".pad.pdf")
    dst.save(tmp, garbage=4, deflate=True)
    dst.close()
    src.close()
    tmp.replace(path)


def uniformize_tight_panel_groups(fig_dir: Path = FIG) -> Dict[str, Any]:
    """After tight savefig, pad each figN group so PNG/PDF share one W×H."""
    from collections import defaultdict

    groups: Dict[str, List[str]] = defaultdict(list)
    for png in sorted(fig_dir.glob("fig*.png")):
        groups[_panel_group_key(png.stem)].append(png.stem)

    report: Dict[str, Any] = {}
    for group, stems in sorted(groups.items()):
        png_sizes = [Image.open(fig_dir / f"{s}.png").size for s in stems]
        import fitz

        pdf_sizes = []
        for s in stems:
            doc = fitz.open(fig_dir / f"{s}.pdf")
            r = doc[0].rect
            pdf_sizes.append((float(r.width), float(r.height)))
            doc.close()
        tw, th = max(w for w, _ in png_sizes), max(h for _, h in png_sizes)
        pw, ph = max(w for w, _ in pdf_sizes), max(h for _, h in pdf_sizes)
        for s in stems:
            _pad_png_centered(fig_dir / f"{s}.png", tw, th)
            _pad_pdf_centered(fig_dir / f"{s}.pdf", pw, ph)
        report[group] = {"png": [tw, th], "pdf_pt": [round(pw, 2), round(ph, 2)], "n": len(stems)}

    for row in MANIFEST_ROWS:
        pdf = OUT / row["final_pdf"]
        if pdf.is_file():
            row["sha256_pdf"] = sha256_file(pdf)
    return report


def compress_broken_y(
    y: float,
    *,
    break_at: float = 300.0,
    top_tick: float = 600.0,
    upper_span: float = 50.0,
) -> float:
    """Piecewise map: [0, break_at] linear; (break_at, top_tick] → short upper_span."""
    y = float(y)
    if y <= break_at:
        return y
    return break_at + (y - break_at) / (float(top_tick) - break_at) * float(upper_span)


def add_left_yaxis_break_mark(
    ax,
    y_break: float,
    *,
    top_tick: float = 600.0,
    upper_span: float = 50.0,
    dx: float = 0.028,
) -> None:
    """Physically cut the LEFT y-spine and place short // marks in the gap (left only)."""
    from matplotlib.patches import Rectangle
    from matplotlib.transforms import blended_transform_factory

    y0, y1 = ax.get_ylim()
    y_top = compress_broken_y(
        float(top_tick), break_at=float(y_break), top_tick=float(top_tick), upper_span=upper_span
    )
    # Large enough gap in the compressed upper band to read as a real cut.
    band = max(y_top - float(y_break), 1e-6)
    gap = 0.55 * band
    y_lo = float(y_break) + 0.10 * band
    y_hi = y_lo + gap
    y_mid = 0.5 * (y_lo + y_hi)

    lw = ax.spines["left"].get_linewidth()
    color = ax.spines["left"].get_edgecolor()
    ax.spines["left"].set_visible(False)

    trans = blended_transform_factory(ax.transAxes, ax.transData)
    # Wide white knockout so spine ink cannot bridge the cut.
    ax.add_patch(
        Rectangle(
            (-0.055, y_lo),
            0.110,
            gap,
            transform=trans,
            facecolor="white",
            edgecolor="none",
            clip_on=False,
            zorder=5.4,
        )
    )
    spine_kw = dict(
        transform=trans,
        color=color,
        linewidth=lw,
        clip_on=False,
        solid_capstyle="butt",
        zorder=5.5,
    )
    ax.plot([0.0, 0.0], [y0, y_lo], **spine_kw)
    ax.plot([0.0, 0.0], [y_hi, y1], **spine_kw)

    # Short diagonals that stay INSIDE the gap (must not bridge the two spine ends).
    dy = 0.18 * gap
    sep = 0.16 * gap
    slash_kw = dict(
        transform=trans,
        color=color,
        linewidth=lw,
        clip_on=False,
        solid_capstyle="butt",
        zorder=6,
    )
    for offset in (-sep, sep):
        ax.plot([-dx, dx], [y_mid + offset - dy, y_mid + offset + dy], **slash_kw)


def apply_compressed_broken_yaxis(
    ax,
    *series: Sequence[float],
    break_at: float = 300.0,
    top_tick: float = 600.0,
    upper_span: float = 50.0,
) -> None:
    """Single continuous axes; tick labels jump break_at → top_tick; left break marks only."""
    y_top = compress_broken_y(float(top_tick), break_at=break_at, top_tick=top_tick, upper_span=upper_span)
    ax.set_ylim(0.0, y_top)
    step = float(break_at) / 3.0
    tick_vals: List[float] = [0.0]
    t = step
    while t < float(break_at) - 1e-9:
        tick_vals.append(t)
        t += step
    tick_vals.extend([float(break_at), float(top_tick)])
    tick_pos = [
        compress_broken_y(v, break_at=break_at, top_tick=top_tick, upper_span=upper_span) for v in tick_vals
    ]
    ax.set_yticks(tick_pos)
    ax.set_yticklabels([_fmt_tick(v) for v in tick_vals])
    ax.minorticks_off()
    ax.margins(y=0)


def _fmt_tick(v: float) -> str:
    if abs(float(v) - round(float(v))) < 1e-9:
        return str(int(round(float(v))))
    return f"{float(v):g}"


def nice_cover_ticks(vmin: float, vmax: float, *, nbins: int = 6) -> List[float]:
    from matplotlib.ticker import MaxNLocator

    vmin, vmax = float(vmin), float(vmax)
    if vmax < vmin:
        vmin, vmax = vmax, vmin
    if abs(vmax - vmin) < 1e-15:
        if abs(vmin) < 1e-12:
            vmin, vmax = 0.0, 1.0
        else:
            d = abs(vmin) * 0.05
            vmin, vmax = vmin - d, vmax + d
    locator = MaxNLocator(nbins=nbins, steps=[1, 2, 2.5, 5, 10], min_n_ticks=3)
    ticks = [float(t) for t in locator.tick_values(vmin, vmax)]
    if len(ticks) < 2:
        ticks = [vmin, vmax]
    step = ticks[1] - ticks[0]
    eps = abs(step) * 1e-9 + 1e-15
    while ticks[0] > vmin + eps:
        ticks.insert(0, ticks[0] - step)
    while ticks[-1] < vmax - eps:
        ticks.append(ticks[-1] + step)
    return ticks


def apply_value_yaxis(ax, *series: Sequence[float], nbins: int = 6, include_zero: bool = False) -> None:
    vals = [float(v) for s in series for v in s]
    if not vals:
        return
    lo, hi = min(vals), max(vals)
    if include_zero:
        lo = min(lo, 0.0)
        hi = max(hi, 0.0)
    ticks = nice_cover_ticks(lo, hi, nbins=nbins)
    ax.set_ylim(ticks[0], ticks[-1])
    ax.set_yticks(ticks)
    ax.set_yticklabels([_fmt_tick(v) for v in ticks])
    ax.minorticks_off()
    ax.margins(y=0)


def extend_yaxis_by_ticks(ax, n_extra: int = 2) -> None:
    """Raise ymax by n_extra major-tick steps; endpoint is a labeled tick."""
    ticks = [float(t) for t in ax.get_yticks()]
    if len(ticks) < 2 or n_extra <= 0:
        return
    step = ticks[1] - ticks[0]
    if abs(step) < 1e-15:
        return
    y0 = float(ax.get_ylim()[0])
    top = ticks[-1]
    for _ in range(int(n_extra)):
        top = top + step
        ticks.append(top)
    ax.set_ylim(y0, top)
    ax.set_yticks(ticks)
    ax.set_yticklabels([_fmt_tick(v) for v in ticks])
    ax.minorticks_off()
    ax.margins(y=0)


def apply_categorical_x(ax, categories: Sequence[Any]) -> List[int]:
    """Equally spaced categorical x; show exact original values; rotation=0."""
    xs = list(range(len(categories)))
    ax.set_xscale("linear")
    ax.set_xticks(xs)
    ax.set_xticklabels([_fmt_tick(v) if isinstance(v, (int, float)) else str(v) for v in categories], rotation=0, ha="center")
    ax.set_xlim(-0.5, len(categories) - 0.5)
    ax.minorticks_off()
    ax.margins(x=0)
    return xs


def apply_log_x(ax, values: Sequence[float], *, base: float = 10.0) -> None:
    """Log x with exact tested-point ticks; rotation=0; no scientific notation."""
    from matplotlib.ticker import FixedLocator, FuncFormatter

    vals = [float(v) for v in values]
    ax.set_xscale("log", base=base)
    ax.xaxis.set_major_locator(FixedLocator(vals))
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _pos: _fmt_tick(v)))
    ax.set_xlim(min(vals), max(vals))
    ax.minorticks_off()
    for label in ax.get_xticklabels():
        label.set_rotation(0)
        label.set_ha("center")


def apply_linear_x(ax, values: Sequence[float]) -> None:
    """Linear numeric x with exact tested-point ticks; rotation=0."""
    from matplotlib.ticker import FixedLocator, FuncFormatter

    vals = [float(v) for v in values]
    ax.set_xscale("linear")
    ax.xaxis.set_major_locator(FixedLocator(vals))
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _pos: _fmt_tick(v)))
    ax.set_xlim(min(vals), max(vals))
    ax.minorticks_off()
    for label in ax.get_xticklabels():
        label.set_rotation(0)
        label.set_ha("center")
    ax.margins(x=0)


def nudge_xtick_labels(ax, offsets_points: Dict[float, float]) -> None:
    """Shift selected x-tick labels horizontally in points (data ticks unchanged)."""
    from matplotlib.transforms import ScaledTranslation

    if not offsets_points:
        return
    fig = ax.figure
    # Stash once so redraw/savefig can re-apply after tick labels are rebuilt.
    ax._nudge_xtick_offsets = {float(k): float(v) for k, v in offsets_points.items()}

    def _apply(_event=None) -> None:
        offs = getattr(ax, "_nudge_xtick_offsets", None) or {}
        for label in ax.get_xticklabels():
            try:
                val = float(label.get_text())
            except ValueError:
                continue
            dx = None
            for key, off in offs.items():
                if abs(float(key) - val) <= 1e-9 * max(1.0, abs(float(key))):
                    dx = float(off)
                    break
            if dx is None:
                continue
            base = getattr(label, "_nudge_base_transform", None)
            if base is None:
                base = label.get_transform()
                label._nudge_base_transform = base
            label.set_transform(base + ScaledTranslation(dx / 72.0, 0.0, fig.dpi_scale_trans))

    if not getattr(ax, "_nudge_xtick_cid", None):
        ax._nudge_xtick_cid = fig.canvas.mpl_connect("draw_event", _apply)
    fig.canvas.draw()
    _apply()


# ---------------------------------------------------------------------------
# Fig.4 — grouped bars (categorical)
# ---------------------------------------------------------------------------


def fig4_panels() -> None:
    data = load_json(DATA / "fig3/fig3_attribute_cost.json")
    mapping = [
        ("fig4a", "gateway_partial_s", "Latency (ms)"),
        ("fig4b", "user_final_dec_s", "Latency (ms)"),
        ("fig4c", "outsourced_enc_s", "Latency (ms)"),
        ("fig4d", "outsourced_dec_s", "Latency (ms)"),
    ]
    width = 0.36
    for stem, key, ylabel in mapping:
        pts = data["panels"][key]
        cats = [float(p["x"]) for p in pts]
        means = [p["y_mean"] for p in pts]
        p95s = [p["y_p95"] for p in pts]
        fig, ax = new_panel()
        xpos = apply_categorical_x(ax, cats)
        ax.bar([x - width / 2 for x in xpos], means, width, label="Mean", color=FIG4_MEAN_COLOR, **BAR_EDGE)
        ax.bar([x + width / 2 for x in xpos], p95s, width, label="P95", color=FIG4_P95_COLOR, **BAR_EDGE)
        apply_value_yaxis(ax, means, p95s, include_zero=stem in ("fig4a", "fig4b"))
        if stem in ("fig4a", "fig4b"):
            extend_yaxis_by_ticks(ax, n_extra=2)
        ax.set_xlabel("Policy leaves")
        ax.set_ylabel(ylabel)
        ax.legend(frameon=False, loc="upper left")
        style_ax(ax)
        save_panel(
            fig,
            stem,
            processed_source="results/data/fig3/fig3_attribute_cost.json",
            raw_source="results/data/E1/20260912T041730Z-b8c2c19a",
            config="experiments/configs/final/E1_crypto.yaml",
            run_id=data["run"],
        )


# ---------------------------------------------------------------------------
# Fig.5 — linear-x line plots
# ---------------------------------------------------------------------------


def fig5_panels() -> None:
    data = load_json(DATA / "fig4/fig4_role_cost.json")
    cfg = ROOT / "experiments/configs/final/E2_role.yaml"

    pts = data["vary_targets"]
    xs = [float(p["x"]) for p in pts]
    means = [p["y_mean"] for p in pts]
    p95s = [p["y_p95"] for p in pts]
    fig, ax = new_panel()
    ax.plot(xs, means, **SCHEME_STYLE["mean_latency"], label="Mean", markersize=MARKER_SIZE)
    ax.plot(xs, p95s, **SCHEME_STYLE["p95_latency"], label="P95", markersize=MARKER_SIZE)
    apply_linear_x(ax, xs)
    apply_value_yaxis(ax, means, p95s)
    ax.set_xlabel("Number of target roles")
    ax.set_ylabel("Role-protection latency (ms)")
    ax.legend(frameon=False)
    style_ax(ax)
    save_panel(
        fig,
        "fig5a",
        processed_source="results/data/fig4/fig4_role_cost.json",
        raw_source="results/data/E2/20260912T042011Z-506190d0",
        config="experiments/configs/final/E2_role.yaml",
        run_id=data["run"],
    )

    pts = data["vary_path"]
    xs = [float(p["x"]) for p in pts]
    means = [p["y_mean"] for p in pts]
    p95s = [p["y_p95"] for p in pts]
    fig, ax = new_panel()
    ax.plot(xs, means, **SCHEME_STYLE["mean_latency"], label="Mean", markersize=MARKER_SIZE)
    ax.plot(xs, p95s, **SCHEME_STYLE["p95_latency"], label="P95", markersize=MARKER_SIZE)
    apply_linear_x(ax, xs)
    apply_value_yaxis(ax, means, p95s)
    ax.set_xlabel("Ancestor / path size")
    ax.set_ylabel("Role-protection latency (ms)")
    ax.legend(frameon=False)
    style_ax(ax)
    save_panel(
        fig,
        "fig5b",
        processed_source="results/data/fig4/fig4_role_cost.json",
        raw_source="results/data/E2/20260912T042011Z-506190d0",
        config="experiments/configs/final/E2_role.yaml",
        run_id=data["run"],
    )
    (DATA / "fig4/fig4_fixed_params.json").write_text(
        json.dumps({"fixed_ancestor_path": 20, "fixed_targets": 4, "config": str(cfg.relative_to(ROOT))}, indent=2),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Fig.6 — linear-x; throughput bars + y=x offered reference + latency lines
# ---------------------------------------------------------------------------


def fig6_panels() -> None:
    rows = load_csv(DATA / "fig5/fig5_source.csv")
    ops = [
        ("fig6a", "resource_management"),
        ("fig6b", "policy_management"),
        ("fig6c", "CommitSegment"),
        ("fig6d", "UpdateAuthorization"),
    ]
    rates = [1.0, 64.0, 256.0, 1536.0, 1792.0, 2560.0]
    # Omit TPS=1 on the plot: batching-dominated and crowds 64 on linear x.
    plot_rates = [64.0, 256.0, 1536.0, 1792.0, 2560.0]
    gaps = [plot_rates[i + 1] - plot_rates[i] for i in range(len(plot_rates) - 1)]
    bar_w = 0.45 * min(gaps)
    for stem, op in ops:
        by_rate = {float(r["target_offered_tps"]): r for r in rows if r["operation"] == op}
        fig, ax, ax2 = new_panel(twin=True)
        thr = [float(by_rate[t]["valid_committed_tps"]) for t in plot_rates]
        mean_ms = [float(by_rate[t]["mean_latency_s"]) * 1000.0 for t in plot_rates]
        p95_ms = [float(by_rate[t]["p95_latency_s"]) * 1000.0 for t in plot_rates]
        apply_linear_x(ax, plot_rates)
        # Extra right pad so the last bar is not clipped; no endpoint tick beyond data.
        ax.set_xlim(0.0, max(plot_rates) + 0.6 * bar_w)
        ax.bar(plot_rates, thr, width=bar_w, color=SCHEME_STYLE["throughput"]["color"], alpha=0.85, label="Committed throughput", zorder=2, align="center", **BAR_EDGE)
        # True y=x reference on shared TPS scales (linear–linear → straight diagonal).
        ax.plot(plot_rates, plot_rates, **SCHEME_STYLE["ideal"], label="Offered rate", zorder=3)
        ax2.plot(plot_rates, mean_ms, **SCHEME_STYLE["mean_latency"], label="Mean latency", markersize=MARKER_SIZE, zorder=4)
        ax2.plot(plot_rates, p95_ms, **SCHEME_STYLE["p95_latency"], label="P95 latency", markersize=MARKER_SIZE, zorder=4)
        apply_value_yaxis(ax, thr, plot_rates, include_zero=True)
        apply_value_yaxis(ax2, mean_ms, p95_ms, include_zero=True)
        ax.set_xlabel("Offered transaction rate (TPS)")
        ax.set_ylabel("Throughput (TPS)")
        ax2.set_ylabel("Latency (ms)")
        h1, l1 = ax.get_legend_handles_labels()
        h2, l2 = ax2.get_legend_handles_labels()
        ax.legend(h1 + h2, l1 + l2, frameon=False, loc="upper center")
        style_ax(ax)
        ax2.spines["top"].set_visible(False)
        ax2.spines["right"].set_visible(True)
        save_panel(
            fig,
            stem,
            processed_source="results/data/fig5/fig5_source.csv",
            raw_source="results/data/E3/",
            config="experiments/configs/final/E3_low_mid.yaml; E3 high_load cells",
            run_id="composite:E3_low_mid+high_load",
        )


# ---------------------------------------------------------------------------
# Fig.7 — linear-x line family
# ---------------------------------------------------------------------------



def fig7_panels() -> None:
    # Fig.7(a) E4_paired — paired open-loop schedules
    e4_run = "20260927T172314Z-642f8d58"
    e4 = load_csv(DATA / "authorization_consistency.csv")
    hs = sorted(
        [r for r in e4 if r.get("scheme") == "HieraStream"],
        key=lambda r: float(r["auth_update_rate"]),
    )
    uv = sorted(
        [r for r in e4 if r.get("scheme") == "unversioned_publication"],
        key=lambda r: float(r["auth_update_rate"]),
    )
    xs = [float(r["auth_update_rate"]) for r in hs]

    def ratio(r: Dict[str, str]) -> float:
        succ = float(r["successful_segment_commits"] or 0)
        stale = float(r["stale_successful_commits"] or 0)
        return stale / succ if succ else 0.0

    hs_ratio = [ratio(r) for r in hs]
    uv_ratio = [ratio(r) for r in uv]
    hs_retry = [float(r["retry_rate"] or 0) for r in hs]
    fig, ax = new_panel()
    ax.plot(xs, hs_ratio, **SCHEME_STYLE["HS_stale"], label="HieraStream stale-success", markersize=MARKER_SIZE)
    ax.plot(xs, uv_ratio, **SCHEME_STYLE["UV_stale"], label="Unversioned stale-success", markersize=MARKER_SIZE)
    ax.plot(xs, hs_retry, **SCHEME_STYLE["HS_retry"], label="HieraStream retry rate", markersize=MARKER_SIZE)
    apply_linear_x(ax, xs)
    apply_value_yaxis(ax, hs_ratio, uv_ratio, hs_retry, include_zero=True)
    _, ymax = ax.get_ylim()
    ax.set_ylim(0.0, ymax)
    ax.set_yticks([t for t in ax.get_yticks() if t >= 0])
    ax.set_yticklabels([_fmt_tick(t) for t in ax.get_yticks()])
    ax.set_xlabel("Authorization-update rate (1/s)")
    ax.set_ylabel("Ratio")
    ax.legend(frameon=False, loc="upper left")
    style_ax(ax)
    save_panel(
        fig,
        "fig7a",
        processed_source="results/data/authorization_consistency.csv",
        raw_source=f"results/data/E4_paired/{e4_run}",
        config="experiments/configs/final/E4_consistency_paired.yaml",
        run_id=e4_run,
    )

    # 6b E6
    e6 = load_csv(DATA / "longitudinal_scalability.csv")
    pts = sorted(e6, key=lambda r: float(r["offered_events_per_sec"]))
    xs = [float(r["offered_events_per_sec"]) for r in pts]
    ys = [float(r["sustained_throughput_eps"]) for r in pts]
    fig, ax = new_panel()
    ax.plot(xs, ys, **SCHEME_STYLE["throughput"], label="Sustained throughput", markersize=MARKER_SIZE)
    ax.plot(xs, xs, **SCHEME_STYLE["ideal"], label="Offered rate")
    apply_linear_x(ax, xs)
    apply_value_yaxis(ax, ys, xs, include_zero=True)
    ax.set_xlabel("Offered replay rate (events/s)")
    ax.set_ylabel("Sustained throughput (events/s)")
    ax.legend(frameon=False)
    style_ax(ax)
    nudge_xtick_labels(ax, {100.0: 6.0, 200.0: 9.0})
    save_panel(
        fig,
        "fig7b",
        processed_source="results/data/fig6/fig6_longitudinal.json",
        raw_source="results/data/E6/20260912T065259Z-eba2f6a4",
        config="experiments/configs/final/E6_longitudinal.yaml",
        run_id="20260912T065259Z-eba2f6a4",
    )

    # 6c E7
    e7 = load_json(DATA / "fig6/segment_granularity.json")
    xs = [float(s) for s in e7["sizes"]]
    fig, ax, ax2 = new_panel(twin=True)
    ax.plot(xs, e7["metadata_per_payload"], **SCHEME_STYLE["metadata"], label="Metadata/payload ratio", markersize=MARKER_SIZE)
    ax2.plot(xs, e7["pub_latency_ms"], **SCHEME_STYLE["pub_lat"], label="Publication latency", markersize=MARKER_SIZE)
    apply_linear_x(ax, xs)
    apply_value_yaxis(ax, e7["metadata_per_payload"], include_zero=True)
    apply_value_yaxis(ax2, e7["pub_latency_ms"], include_zero=True)
    ax.set_xlabel("Target segment size (bytes)")
    ax.set_ylabel("Metadata/payload ratio")
    ax2.set_ylabel("Publication latency (ms)")
    h1, l1 = ax.get_legend_handles_labels()
    h2, l2 = ax2.get_legend_handles_labels()
    ax.legend(h1 + h2, l1 + l2, frameon=False, loc="upper right")
    style_ax(ax)
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(True)
    nudge_xtick_labels(ax, {1024.0: 9.0})
    save_panel(
        fig,
        "fig7c",
        processed_source="results/data/fig6/segment_granularity.json",
        raw_source="results/data/E7/20260912T115548Z-9e5e8618",
        config="experiments/configs/final/E7_segment.yaml",
        run_id=e7["run"],
    )

    # 6d E8
    e8 = load_csv(DATA / "e8_history.csv")
    hs = sorted([r for r in e8 if r["scheme"] == "HieraStream"], key=lambda r: int(r["historical_segments"]))
    hist = sorted(
        [r for r in e8 if r["scheme"] == "historical_ciphertext_update"],
        key=lambda r: int(r["historical_segments"]),
    )
    xs = [float(r["historical_segments"]) for r in hs]
    hs_ms = [float(r["revocation_latency_s"]) * 1000.0 for r in hs]
    hist_ms = [float(r["revocation_latency_s"]) * 1000.0 for r in hist]
    fig, ax = new_panel()
    ax.plot(xs, hs_ms, **SCHEME_STYLE["HieraStream"], label="HieraStream", markersize=MARKER_SIZE)
    ax.plot(xs, hist_ms, **SCHEME_STYLE["Historical-update"], label="Historical-update", markersize=MARKER_SIZE)
    apply_linear_x(ax, xs)
    apply_value_yaxis(ax, hs_ms, hist_ms, include_zero=True)
    # Small negative pad so near-zero HieraStream is visible; do not label negative ticks.
    _, ymax = ax.get_ylim()
    ax.set_ylim(-20.0, ymax)
    ax.set_yticks([t for t in ax.get_yticks() if t >= 0])
    ax.set_yticklabels([_fmt_tick(t) for t in ax.get_yticks()])
    ax.set_xlabel("Historical segment count")
    ax.set_ylabel("Revocation/update latency (ms)")
    ax.legend(frameon=False, loc="upper left")
    style_ax(ax)
    nudge_xtick_labels(ax, {50.0: 3, 100.0: 6})

    # Lower-right categorical inset under Historical-update; clear of x-axis labels.
    axins = ax.inset_axes([0.46, 0.16, 0.50, 0.18])
    axins.set_facecolor("white")
    axins.patch.set_alpha(1.0)
    xpos = list(range(len(xs)))
    axins.plot(xpos, hs_ms, **SCHEME_STYLE["HieraStream"], markersize=MARKER_SIZE_INSET)
    axins.set_xticks(xpos)
    axins.set_xticklabels([_fmt_tick(v) for v in xs], rotation=0, ha="center")
    apply_value_yaxis(axins, hs_ms, nbins=3)
    axins.tick_params(axis="both", labelsize=5.2, pad=1)
    axins.set_title("HieraStream", fontsize=6, pad=1)
    axins.set_zorder(5)
    for spine in axins.spines.values():
        spine.set_zorder(6)
    save_panel(
        fig,
        "fig7d",
        processed_source="results/data/authorization_consistency.csv",
        raw_source="results/data/E8/20260912T042510Z-33808d5d",
        config="experiments/configs/final/E8_history.yaml",
        run_id="20260912T042510Z-33808d5d",
    )


def fig8_panels() -> None:
    data = load_json(DATA / "fig7/fig7_crypto_comparison.json")
    if data.get("run") != "20260913T154655Z-a5e3d0d8":
        raise RuntimeError(f"unexpected Fig.8 run: {data.get('run')}")
    cats = [float(p["policy_size"]) for p in data["series"]["HieraStream"]]
    schemes = ["HieraStream", "CP-ABE", "PASH", "MASS"]
    n = len(schemes)
    width = 0.18
    # Visual length of the compressed upper band (break_at → top_tick); larger ⇒ 600 farther from 300.
    upper_span = 90.0
    for stem, field, ylabel, break_at, top_tick in [
        ("fig8a", "protect_mean", "Protection latency (ms)", 300.0, 600.0),
        ("fig8b", "recover_mean", "Recovery latency (ms)", 150.0, 350.0),
    ]:
        series_ys = [[p[field] * 1000.0 for p in data["series"][sch]] for sch in schemes]
        fig, ax = new_panel()
        xpos = apply_categorical_x(ax, cats)
        for i, sch in enumerate(schemes):
            ys = [
                compress_broken_y(v, break_at=break_at, top_tick=top_tick, upper_span=upper_span)
                for v in series_ys[i]
            ]
            offset = (i - (n - 1) / 2) * width
            ax.bar([x + offset for x in xpos], ys, width, label=sch, color=SCHEME_STYLE[sch]["color"], **BAR_EDGE)
        apply_compressed_broken_yaxis(
            ax, *series_ys, break_at=break_at, top_tick=top_tick, upper_span=upper_span
        )
        ax.set_xlabel("Policy leaves")
        ax.set_ylabel(ylabel)
        ax.legend(frameon=False)
        style_ax(ax)
        add_left_yaxis_break_mark(ax, float(break_at), top_tick=float(top_tick), upper_span=upper_span)
        save_panel(
            fig,
            stem,
            processed_source="results/data/fig7/fig7_crypto_comparison.json",
            raw_source="results/data/E10/20260913T154655Z-a5e3d0d8",
            config="E10B formal runner",
            run_id="20260913T154655Z-a5e3d0d8",
        )



# ---------------------------------------------------------------------------
# Fig.9 — system baselines (in-process HieraStream / Droplet / TimeCrypt).
# ---------------------------------------------------------------------------

FIG9_RUN = "20260919T181630Z"
FIG9_SCHEMES = ("HieraStream", "Droplet", "TimeCrypt")
FIG9_PAYLOADS = (256, 1024, 4096, 16384)
FIG9_MARKER = 4.0
FIG9_PANEL = (2.60, 2.08)


def _fig9_mean(xs: Sequence[float]) -> float:
    return sum(xs) / len(xs)


def _fig9_p95(xs: Sequence[float]) -> float:
    s = sorted(xs)
    return s[min(len(s) - 1, int(round(0.95 * (len(s) - 1))))]


def _fig9_kib(n: int) -> float:
    return n / 1024.0


def _load_fig9(data_dir: Path) -> Tuple[List[dict], List[dict]]:
    if "20260919T173812Z" in str(data_dir):
        raise RuntimeError(f"refusing superseded baseline path {data_dir}")
    lat_path = data_dir / "raw_latency.jsonl"
    tp_path = data_dir / "raw_throughput.jsonl"
    if not lat_path.is_file() or not tp_path.is_file():
        raise RuntimeError(f"missing system-baseline latency/throughput under {data_dir}")
    env_path = data_dir / "environment.json"
    if env_path.is_file():
        env = json.loads(env_path.read_text(encoding="utf-8"))
        if env.get("payload_seed") not in (None, "hierastream-round2-payload-v1"):
            raise RuntimeError(f"unexpected payload seed {env.get('payload_seed')!r}")
        if env.get("failures"):
            raise RuntimeError(f"environment records failures: {env['failures']}")
    latency = [json.loads(line) for line in lat_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    throughput = [json.loads(line) for line in tp_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return latency, throughput


def _check_fig9(latency: List[dict], throughput: List[dict]) -> None:
    """Fail early if Fig.9 anchor statistics do not match the frozen run."""
    expected_e2e = {
        "HieraStream": (0.187, 0.217, 200),
        "Droplet": (0.428, 0.494, 200),
        "TimeCrypt": (3.223, 4.807, 200),
    }
    expected_size = {"HieraStream": 5785, "Droplet": 4299, "TimeCrypt": 23436}
    expected_tp = {"HieraStream": 1567.4, "Droplet": 1597.3, "TimeCrypt": 777.7}
    problems: List[str] = []
    for scheme, (mean_e, p95_e, n_e) in expected_e2e.items():
        rows = [
            r
            for r in latency
            if r["scheme"] == scheme and r["payload_size"] == 4096 and r.get("success") is True
        ]
        xs = [float(r["e2e_latency_ms"]) for r in rows]
        got = (_fig9_mean(xs), _fig9_p95(xs), len(xs))
        if got[2] != n_e or abs(got[0] - mean_e) > 0.0015 or abs(got[1] - p95_e) > 0.0015:
            problems.append(f"{scheme} 4 KiB E2E {got} != {(mean_e, p95_e, n_e)}")
        for r in rows:
            total = int(r["total_bytes"])
            parts = (
                int(r["protected_payload_bytes"])
                + int(r["crypto_metadata_bytes"])
                + int(r["other_serialized_metadata_bytes"])
            )
            if parts != total:
                problems.append(f"{scheme} byte split {parts} != total {total}")
        first = next(r for r in latency if r["scheme"] == scheme and r["payload_size"] == 4096)
        size = int(first["total_bytes"])
        if size != expected_size[scheme]:
            problems.append(f"{scheme} 4 KiB size {size} != {expected_size[scheme]}")
        cell = next(r for r in throughput if r["scheme"] == scheme and r["offered_tps"] == 1600)
        sustained = float(cell["sustained_throughput"])
        if int(cell["failures"]) != 0 or abs(sustained - expected_tp[scheme]) > 0.15:
            problems.append(f"{scheme} 1600 eps {sustained} failures {cell['failures']}")
    if any(int(r.get("failures", 0)) != 0 for r in throughput):
        problems.append("throughput file contains failures")
    if problems:
        raise RuntimeError("Fig.9 sanity check failed: " + "; ".join(problems))


def _fig9_legend(ax, loc: str, extra: Sequence[str] = ()) -> None:
    wanted = list(FIG9_SCHEMES) + list(extra)
    handles, labels = [], []
    for handle, label in zip(*ax.get_legend_handles_labels()):
        if label in wanted and label not in labels:
            handles.append(handle)
            labels.append(label)
    order = {name: i for i, name in enumerate(wanted)}
    pairs = sorted(zip(handles, labels), key=lambda hl: order.get(hl[1], 99))
    if pairs:
        ax.legend(
            [h for h, _ in pairs],
            [lab for _, lab in pairs],
            frameon=False,
            loc=loc,
            handlelength=2.4,
            borderaxespad=0.2,
        )


def _fig9_ax():
    fig, ax = plt.subplots(figsize=FIG9_PANEL)
    style_ax(ax)
    ax.tick_params(length=3.0, width=0.6, pad=1.5)
    ax.set_axisbelow(True)
    return fig, ax


def _plot_fig9_ecdf(ax, latency: List[dict]) -> None:
    for scheme in FIG9_SCHEMES:
        xs = sorted(
            float(r["e2e_latency_ms"])
            for r in latency
            if r["scheme"] == scheme and r["payload_size"] == 4096 and r.get("success") is True
        )
        n = len(xs)
        ys = [(i + 1) / n for i in range(n)]
        st = SCHEME_STYLE[scheme]
        ax.step(xs, ys, where="post", color=st["color"], linestyle="-", label=scheme, zorder=3)
        stride = max(1, n // 8)
        offset = {"HieraStream": 0, "Droplet": stride // 3, "TimeCrypt": (2 * stride) // 3}[scheme]
        ax.plot(
            xs[offset::stride],
            ys[offset::stride],
            linestyle="none",
            marker=st["marker"],
            color=st["color"],
            markersize=FIG9_MARKER,
            markeredgewidth=0.0,
            zorder=4,
            clip_on=True,
        )
    ax.set_yticks([0.0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.set_ylim(0.0, 1.0)
    ax.margins(y=0.0)
    ax.tick_params(axis="y", direction="in", length=2.8)
    # Custom left spine ending exactly at 1.0 (default spine can overshoot the top tick).
    ax.spines["left"].set_visible(False)
    spine_tf = mtransforms.blended_transform_factory(ax.transAxes, ax.transData)
    ax.plot(
        [0.0, 0.0],
        [0.0, 1.0],
        transform=spine_tf,
        color="black",
        linewidth=0.8,
        solid_capstyle="butt",
        clip_on=False,
        zorder=10,
    )
    ax.set_xlim(0.0, 10.0)
    ax.set_xticks([0, 2, 4, 6, 8, 10])
    ax.spines["bottom"].set_bounds(0.0, 10.0)
    ax.set_xlabel("End-to-end latency (ms)")
    ax.set_ylabel("Cumulative probability")
    _fig9_legend(ax, "lower right")
    ax.set_ylim(0.0, 1.0)


def _plot_fig9_size(ax, latency: List[dict]) -> None:
    series = {scheme: [] for scheme in FIG9_SCHEMES}
    for scheme in FIG9_SCHEMES:
        for n in FIG9_PAYLOADS:
            row = next(r for r in latency if r["scheme"] == scheme and r["payload_size"] == n)
            series[scheme].append((n, int(row["total_bytes"])))
    xs = [_fig9_kib(n) for n in FIG9_PAYLOADS]
    # Same gray dotted baseline as the other figures; kept under the solid curves.
    ax.plot(
        [0.0, 18.0],
        [0.0, 18.0],
        color=SCHEME_STYLE["ideal"]["color"],
        linestyle=SCHEME_STYLE["ideal"]["linestyle"],
        linewidth=1.4,
        label="Plaintext size",
        zorder=1,
    )
    for scheme in FIG9_SCHEMES:
        st = SCHEME_STYLE[scheme]
        ys = [_fig9_kib(total) for _n, total in series[scheme]]
        ax.plot(
            xs,
            ys,
            color=st["color"],
            linestyle="-",
            marker=st["marker"],
            markersize=FIG9_MARKER,
            markeredgewidth=0.0,
            label=scheme,
            zorder=3,
        )
    offsets = {"HieraStream": (6, 6), "Droplet": (6, -10), "TimeCrypt": (6, -4)}
    for scheme in FIG9_SCHEMES:
        n, total = series[scheme][2]
        ratio = total / n
        ax.annotate(
            f"{ratio:.2f}×",
            (_fig9_kib(n), _fig9_kib(total)),
            textcoords="offset points",
            xytext=offsets[scheme],
            fontsize=8,
            color=SCHEME_STYLE[scheme]["color"],
            ha="left",
            va="center",
        )
    ax.set_xlim(0.0, 18.0)
    ax.set_ylim(0.0, 100.0)
    ax.set_xticks(xs)
    # 0.25 and 1 sit close on the linear axis; nudge the "1" label right of "0.25".
    ax.set_xticklabels(["0.25", "1", "4", "16"])
    ax.set_yticks([0, 20, 40, 60, 80, 100])
    ax.set_xlabel("Logical payload size (KiB)")
    ax.set_ylabel("Size (KiB)")
    _fig9_legend(ax, "upper left", extra=("Plaintext size",))
    nudge_xtick_labels(ax, {1.0: 8.0})


def _plot_fig9_throughput(ax, throughput: List[dict]) -> None:
    # Same gray dotted baseline as fig9b; kept under the solid curves.
    ax.plot(
        [0, 1800],
        [0, 1800],
        color=SCHEME_STYLE["ideal"]["color"],
        linestyle=SCHEME_STYLE["ideal"]["linestyle"],
        linewidth=1.4,
        label="Ideal",
        zorder=1,
    )
    for scheme in FIG9_SCHEMES:
        rows = sorted(
            (r for r in throughput if r["scheme"] == scheme and int(r["failures"]) == 0),
            key=lambda r: r["offered_tps"],
        )
        st = SCHEME_STYLE[scheme]
        ax.plot(
            [r["offered_tps"] for r in rows],
            [r["sustained_throughput"] for r in rows],
            color=st["color"],
            linestyle="-",
            marker=st["marker"],
            markersize=FIG9_MARKER,
            markeredgewidth=0.0,
            label=scheme,
            zorder=3,
        )
    ax.set_xlim(0, 1750)
    ax.set_ylim(0, 1800)
    ax.minorticks_off()
    ax.set_xticks([0, 400, 800, 1200, 1600])
    ax.set_yticks([0, 400, 800, 1200, 1600])
    ax.set_xlabel("Offered rate (events/s)")
    ax.set_ylabel("Throughput (events/s)")
    _fig9_legend(ax, "upper left", extra=("Ideal",))


def fig9_panels() -> None:
    """HieraStream / Droplet / TimeCrypt system-level panels."""
    meta = load_json(DATA / "fig8/meta.json")
    if meta.get("run") != FIG9_RUN:
        raise RuntimeError(f"unexpected Fig.9 run: {meta.get('run')}")
    latency, throughput = _load_fig9(DATA / "fig8")
    _check_fig9(latency, throughput)
    drawers = (
        ("fig9a", _plot_fig9_ecdf, latency),
        ("fig9b", _plot_fig9_size, latency),
        ("fig9c", _plot_fig9_throughput, throughput),
    )
    for stem, draw, rows in drawers:
        fig, ax = _fig9_ax()
        draw(ax, rows)
        save_panel(
            fig,
            stem,
            processed_source="results/data/fig8/fig8_system_baseline_summary.json",
            raw_source=f"results/data/system_baselines/{FIG9_RUN}",
            config="scripts/reproduce/generate_publication_figures.py",
            run_id=FIG9_RUN,
        )


def write_manifest() -> None:
    """Panel metadata is not written to disk; packaging uses TRACE in-memory."""
    return


def record_trace(
    name: str,
    *,
    experiment: str,
    run: str,
    data_csv: str,
    script: str,
    pdf: Path,
    png: Path,
) -> None:
    TRACE.append(
        {
            "semantic_name": name,
            "source_experiment": experiment,
            "source_run": run,
            "processed_csv": data_csv,
            "plot_script": script,
            "sha256_pdf": sha256(pdf),
            "final_pdf": str(pdf.relative_to(OUT)),
            "final_png": str(png.relative_to(OUT)),
        }
    )


def save_design_asset(fig: plt.Figure, name: str, *, experiment: str, run: str, data_csv: str) -> None:
    PIC.mkdir(parents=True, exist_ok=True)
    pdf = PIC / f"{name}.pdf"
    png = PIC / f"{name}.png"
    fig.savefig(pdf)
    fig.savefig(png)
    plt.close(fig)
    record_trace(
        name,
        experiment=experiment,
        run=run,
        data_csv=data_csv,
        script=PLOT_SCRIPT,
        pdf=pdf,
        png=png,
    )


def copy_generated_figures() -> None:
    """Copy panels into prefixed publication names under results/figures/."""
    PIC.mkdir(parents=True, exist_ok=True)
    e7_run = ""
    e7_json = DATA / "fig6/segment_granularity.json"
    if e7_json.is_file():
        e7_run = str(load_json(e7_json).get("run") or "")

    for spec in FIGURE_COPY_SPEC:
        stem = spec["stem"]
        semantic = spec["semantic"]
        run = e7_run if stem == "fig7c" else spec["run"]
        if stem == "fig7c" and not run:
            run = "20260912T115548Z-9e5e8618"

        for ext in ("pdf", "png"):
            src = FIG / f"{stem}.{ext}"
            if not src.is_file():
                raise FileNotFoundError(
                    f"Missing generated figure {src}; plot panels before packaging"
                )
            dst = PIC / f"{semantic}.{ext}"
            shutil.copy2(src, dst)

        pdf = PIC / f"{semantic}.pdf"
        png = PIC / f"{semantic}.png"
        record_trace(
            semantic,
            experiment=spec["experiment"],
            run=run,
            data_csv=spec["data_csv"],
            script=PLOT_SCRIPT,
            pdf=pdf,
            png=png,
        )


def export_conference_system_model() -> None:
    """Keep packaged Fig.1 system-model figure."""
    png = PIC / "fig1-system_model.png"
    pdf = PIC / "fig1-system_model.pdf"
    if not pdf.is_file() or not png.is_file():
        raise FileNotFoundError(
            "results/figures/fig1-system_model.{pdf,png} missing"
        )
    record_trace(
        "fig1-system_model",
        experiment="design",
        run="results/figures/fig1-system_model",
        data_csv="",
        script=PLOT_SCRIPT,
        pdf=pdf,
        png=png,
    )


def make_workflow() -> None:
    """Authorization workflow schematic (prepare / commit / activate)."""
    fig, ax = plt.subplots(figsize=(7.0, 5.8))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 13)
    ax.axis("off")
    steps = [
        (1, "Read authorization snapshot"),
        (2, "Gateway partial protection"),
        (3, "Outsourced attribute protection"),
        (4, "Hierarchical role protection"),
        (5, "Payload encryption"),
        (6, "Local metadata / CID preparation"),
        (7, "CommitSegment"),
        (8, "Fabric snapshot / MVCC validation"),
        (9, "Publish metadata after valid commit"),
        (10, "Access / outsourced recovery"),
        (11, "UpdateAuthorization"),
        (12, "Affected-envelope regeneration; retry on stale state"),
    ]
    y0 = 12.2
    for i, (n, text) in enumerate(steps):
        y = y0 - i * 0.92
        fc = "#e8f1fb"
        if n in (7, 8, 9):
            fc = "#fdeeee"
        if n in (11, 12):
            fc = "#fff4e5"
        ax.add_patch(
            FancyBboxPatch(
                (1.2, y - 0.32),
                7.6,
                0.72,
                boxstyle="round,pad=0.02,rounding_size=0.06",
                linewidth=0.8,
                edgecolor="black",
                facecolor=fc,
            )
        )
        ax.text(1.45, y, f"{n}. {text}", ha="left", va="center", fontsize=7.5)
        if i < len(steps) - 1:
            ax.annotate("", xy=(5.0, y - 0.42), xytext=(5.0, y - 0.32), arrowprops=dict(arrowstyle="->", lw=0.8))
    ax.text(0.35, 10.5, "Prepare", rotation=90, va="center", fontsize=8)
    ax.text(0.35, 6.0, "Commit /\nActivate", rotation=90, va="center", fontsize=8, color="#a33")
    ax.text(0.35, 2.2, "Update", rotation=90, va="center", fontsize=8)
    ax.text(5.0, 0.35, "Metadata is published only after a valid commit.", ha="center", fontsize=7)
    save_design_asset(
        fig,
        "fig2-authorization_workflow",
        experiment="journal_design",
        run="n/a",
        data_csv="",
    )


def write_attr_data() -> None:
    src = load_json(DATA / "fig3/fig3_attribute_cost.json")
    rows = []
    mapping = [
        ("attr_gateway_partial", "gateway_partial_s"),
        ("attr_user_final", "user_final_dec_s"),
        ("attr_outsourced_encryption", "outsourced_enc_s"),
        ("attr_outsourced_decryption", "outsourced_dec_s"),
    ]
    for name, key in mapping:
        for p in src["panels"][key]:
            rows.append(
                {
                    "panel": name,
                    "policy_leaves": int(p["x"]),
                    "mean_ms": p["y_mean"],
                    "p95_ms": p["y_p95"],
                    "n": p["n"],
                }
            )
    write_csv(DATA / "attr_crypto_cost.csv", rows)


def write_role_data() -> None:
    src = load_json(DATA / "fig4/fig4_role_cost.json")
    rows = []
    for name, key, fixed_note in [
        ("role_target_scaling", "vary_targets", "fixed_path=20"),
        ("role_path_scaling", "vary_path", "fixed_targets=4"),
    ]:
        for p in src[key]:
            rows.append(
                {
                    "panel": name,
                    "x": int(p["x"]),
                    "mean_ms": p["y_mean"],
                    "p95_ms": p["y_p95"],
                    "n": p["n"],
                    "fixed_setting": fixed_note,
                }
            )
    write_csv(DATA / "role_cost.csv", rows)


def write_fabric_data() -> None:
    rows_src = load_csv(DATA / "fig5/fig5_source.csv")
    rates = [1.0, 64.0, 256.0, 1536.0, 1792.0, 2560.0]
    mapping = [
        ("fabric_resource_management", "resource_management"),
        ("fabric_policy_management", "policy_management"),
        ("fabric_commit_segment", "CommitSegment"),
        ("fabric_update_authorization", "UpdateAuthorization"),
    ]
    out_rows = []
    for name, op in mapping:
        by = {float(r["target_offered_tps"]): r for r in rows_src if r["operation"] == op}
        for t in rates:
            r = by[t]
            out_rows.append(
                {
                    "operation": op,
                    "asset": name,
                    "offered_tps": t,
                    "valid_committed_tps": float(r["valid_committed_tps"]),
                    "mean_latency_ms": float(r["mean_latency_s"]) * 1000,
                    "p95_latency_ms": float(r["p95_latency_s"]) * 1000,
                    "transaction_failure_rate": float(r["transaction_failure_rate"]),
                    "limiting_factor": r["limiting_factor"],
                    "bound_hit_any": r["bound_hit_any"],
                }
            )
    write_csv(DATA / "fabric_performance.csv", out_rows)


def write_longitudinal_data() -> None:
    # E6
    e6 = list(load_csv(DATA / "longitudinal_scalability.csv"))
    e6 = sorted(e6, key=lambda r: float(r["offered_events_per_sec"]))
    rows = []
    for r in e6:
        rows.append(
            {
                "offered_events_per_sec": float(r["offered_events_per_sec"]),
                "sustained_throughput_eps": float(r["sustained_throughput_eps"]),
                "saturated": r["saturated"],
                "dataset": r.get("dataset", ""),
            }
        )
    write_csv(DATA / "longitudinal_scalability.csv", rows)

    # E7
    e7 = load_json(DATA / "fig6/segment_granularity.json")
    rows = []
    for i, s in enumerate(e7["sizes"]):
        rows.append(
            {
                "target_segment_bytes": s,
                "metadata_per_payload_ratio": e7["metadata_per_payload"][i],
                "publication_latency_ms": e7["pub_latency_ms"][i],
                "median_non_tail_bytes": e7["median_non_tail"][i],
            }
        )
    write_csv(DATA / "segment_granularity.csv", rows)

    # E4_paired aggregate rows (paired open-loop)
    e4_run = "20260927T172314Z-642f8d58"
    e4 = load_csv(DATA / "authorization_consistency.csv")
    hs = sorted(
        [r for r in e4 if r.get("scheme") == "HieraStream"],
        key=lambda r: float(r["auth_update_rate"]),
    )
    uv = sorted(
        [r for r in e4 if r.get("scheme") == "unversioned_publication"],
        key=lambda r: float(r["auth_update_rate"]),
    )

    def ratio(r):
        succ = float(r["successful_segment_commits"] or 0)
        stale = float(r["stale_successful_commits"] or 0)
        return stale / succ if succ else 0.0

    rows = []
    for r in hs:
        rows.append(
            {
                "scheme": "HieraStream",
                "auth_update_rate": float(r["auth_update_rate"]),
                "successful_segment_commits": int(float(r["successful_segment_commits"])),
                "stale_successful_commits": int(float(r["stale_successful_commits"])),
                "stale_success_ratio": ratio(r),
                "retry_rate": float(r["retry_rate"] or 0),
                "ratio_definition": "stale_successful_commits / successful_segment_commits (pooled)",
                "design": "paired_open_loop",
                "run_id": e4_run,
            }
        )
    for r in uv:
        rows.append(
            {
                "scheme": "unversioned_publication",
                "auth_update_rate": float(r["auth_update_rate"]),
                "successful_segment_commits": int(float(r["successful_segment_commits"])),
                "stale_successful_commits": int(float(r["stale_successful_commits"])),
                "stale_success_ratio": ratio(r),
                "retry_rate": "",
                "ratio_definition": "stale_successful_commits / successful_segment_commits (pooled)",
                "design": "paired_open_loop",
                "run_id": e4_run,
            }
        )
    write_csv(DATA / "authorization_consistency.csv", rows)

    # E8
    e8 = load_csv(DATA / "e8_history.csv")
    hs = sorted([r for r in e8 if r["scheme"] == "HieraStream"], key=lambda r: int(r["historical_segments"]))
    hist = sorted(
        [r for r in e8 if r["scheme"] == "historical_ciphertext_update"],
        key=lambda r: int(r["historical_segments"]),
    )
    rows = []
    for r in hs + hist:
        rows.append(
            {
                "scheme": "HieraStream" if r["scheme"] == "HieraStream" else "Historical-update",
                "historical_segments": int(r["historical_segments"]),
                "revocation_latency_ms": float(r["revocation_latency_s"]) * 1000,
                "historical_ciphertexts_modified": int(float(r["historical_ciphertexts_modified"] or 0)),
                "bytes_communicated": int(float(r["bytes_communicated"] or 0)),
            }
        )
    write_csv(DATA / "revocation_history.csv", rows)


def write_baseline_data() -> None:
    src = load_json(DATA / "fig7/fig7_crypto_comparison.json")
    if src.get("run") != "20260913T154655Z-a5e3d0d8":
        raise RuntimeError(f"unexpected E10 run: {src.get('run')}")
    rows = []
    for sch in ["HieraStream", "CP-ABE", "PASH", "MASS"]:
        for p in src["series"][sch]:
            rows.append(
                {
                    "scheme": sch,
                    "policy_size": p["policy_size"],
                    "protect_mean_ms": p["protect_mean"] * 1000,
                    "recover_mean_ms": p["recover_mean"] * 1000,
                    "protect_p95_ms": p["protect_p95"] * 1000,
                    "recover_p95_ms": p["recover_p95"] * 1000,
                    "N": p["protect_N"],
                }
            )
    write_csv(DATA / "baseline_comparison.csv", rows)


def write_system_baseline_data() -> None:
    """Manuscript CSV for Fig.9 HieraStream/Droplet/TimeCrypt comparison."""
    summary = load_json(DATA / "fig8/fig8_system_baseline_summary.json")
    if summary.get("run") != "20260919T181630Z":
        raise RuntimeError(f"unexpected system-baseline run: {summary.get('run')}")
    rows = []
    for sch, payload in summary["schemes"].items():
        for nbytes, size in payload["sizes"].items():
            n = int(nbytes)
            e2e = payload["e2e_4kib"] if n == 4096 else {}
            tp1600 = summary["throughput"][sch].get("1600", {})
            rows.append(
                {
                    "scheme": sch,
                    "payload_bytes": n,
                    "total_serialized_bytes": size["total_bytes"],
                    "encrypted_payload_bytes": size["encrypted_payload_bytes"],
                    "crypto_metadata_bytes": size["crypto_metadata_bytes"],
                    "other_serialized_metadata_bytes": size["other_serialized_metadata_bytes"],
                    "expansion_ratio": size["expansion_ratio"],
                    "e2e_mean_ms": e2e.get("mean", ""),
                    "e2e_p95_ms": e2e.get("p95", ""),
                    "e2e_n": e2e.get("n", ""),
                    "sustained_throughput_1600": tp1600.get("sustained_throughput", "") if n == 4096 else "",
                }
            )
    write_csv(DATA / "system_baseline_comparison.csv", rows)


def build_tables() -> None:
    TAB.mkdir(parents=True, exist_ok=True)
    ds_rows = [
        {
            "Dataset": "UCI Heart Failure",
            "Data type": "Clinical tabular records",
            "Evaluation scope": "Complete public set (299 records)",
            "Temporal characteristic": "Static / one-segment compatibility",
            "Evaluation role": "Pipeline compatibility",
        },
        {
            "Dataset": "HF Remote Monitoring",
            "Data type": "Longitudinal weight traces",
            "Evaluation scope": "Public Zenodo CSVs: 10 subject IDs; WEIGHT only (no HR/BP columns in shipped exemplars)",
            "Temporal characteristic": "Longitudinal remote monitoring",
            "Evaluation role": "Pipeline compatibility",
        },
        {
            "Dataset": "HM3 Synthetic LVAD",
            "Data type": "Synthetic physiological traces",
            "Evaluation scope": "Explicitly synthetic/simulated",
            "Temporal characteristic": "Synthetic longitudinal stream",
            "Evaluation role": "Controlled pipeline stress",
        },
        {
            "Dataset": "VitalDB",
            "Data type": "Intraoperative vital signs",
            "Evaluation scope": "Experiment-specific subsets/traces (not full 6388-case corpus)",
            "Temporal characteristic": "High-rate clinical stream",
            "Evaluation role": "Pipeline / longitudinal compatibility",
        },
    ]
    write_csv(TAB / "dataset_summary.csv", ds_rows)
    (TAB / "dataset_summary.tex").write_text(
        r"""\begin{tabular}{|l|l|l|l|l|}
\hline
\textbf{Dataset} & \textbf{Data type} & \textbf{Evaluation scope} & \textbf{Temporal characteristic} & \textbf{Evaluation role} \\
\hline
UCI Heart Failure & Clinical tabular records & Complete public set (299 records) & Static / one-segment compatibility & Pipeline compatibility \\
\hline
HF Remote Monitoring & Longitudinal weight traces & Public Zenodo CSVs: 10 subject IDs; WEIGHT only & Longitudinal remote monitoring & Pipeline compatibility \\
\hline
HM3 Synthetic LVAD & Synthetic physiological traces & Explicitly synthetic/simulated & Synthetic longitudinal stream & Controlled pipeline stress \\
\hline
VitalDB & Intraoperative vital signs & Experiment-specific subsets (not full corpus) & High-rate clinical stream & Pipeline / longitudinal compatibility \\
\hline
\end{tabular}
""",
        encoding="utf-8",
    )

    e9 = [r for r in load_csv(DATA / "e9/datasets.csv") if r.get("payload_bytes")]
    by = {r["dataset"]: r for r in e9}
    names = {
        "uci_heart_failure": "UCI Heart Failure",
        "hf_remote_monitoring": "HF Remote Monitoring",
        "hm3_synthetic": "HM3 Synthetic",
        "vitaldb": "VitalDB",
    }
    scale = {
        "uci_heart_failure": "299 records",
        "hf_remote_monitoring": "10 subjects / 80 events",
        "hm3_synthetic": "Synthetic; 80 events",
        "vitaldb": "Subset; 80 events",
    }
    pipe_rows = []
    tex_lines = []
    for ds, label in names.items():
        r = by[ds]
        payload = float(r["payload_bytes"])
        meta = float(r["metadata_bytes"])
        accepted = float(r["accepted_events"])
        segs = float(r["segments"])
        pipe_rows.append(
            {
                "Dataset": label,
                "Evaluation scale": scale[ds],
                "Segment size": "1 record/segment",
                "Replay rate (events/s)": r["replay_rate_eps"],
                "Throughput (events/s)": float(r["throughput_eps"]),
                "Pipeline latency mean (ms)": float(r["e2e_latency_s_mean"]) * 1000,
                "Avg payload bytes": payload / max(1, segs),
                "Avg metadata bytes": meta / max(1, segs),
                "Metadata-to-payload byte ratio": float(r["metadata_overhead"]),
                "metadata_ratio_definition": "sum(len(metadata_bytes(metadata_obj))) / sum(payload_bytes) over accepted segments",
                "Accepted events": accepted,
                "Claim boundary": "pipeline compatibility (not clinical validation)",
            }
        )
        tex_lines.append(
            f"{label} & {scale[ds]} & 1 record/segment & {float(r['replay_rate_eps']):.0f} & "
            f"{float(r['throughput_eps']):.2f} & {float(r['e2e_latency_s_mean'])*1000:.2f} & "
            f"{payload/max(1,segs):.1f} & {meta/max(1,segs):.1f} & {float(r['metadata_overhead']):.2f} \\\\"
        )
    write_csv(TAB / "pipeline_summary.csv", pipe_rows)
    (TAB / "pipeline_summary.tex").write_text(
        r"""\begin{tabular}{|l|l|l|c|c|c|c|c|c|}
\hline
\textbf{Dataset} & \textbf{Scale} & \textbf{Segment size} & \textbf{Replay rate} & \textbf{Throughput} & \textbf{Latency} & \textbf{Avg payload} & \textbf{Avg metadata} & \textbf{Meta/payload} \\
 &  &  & (events/s) & (events/s) & mean (ms) & (B) & (B) & ratio \\
\hline
"""
        + "\n".join(tex_lines)
        + r"""
\hline
\end{tabular}
""",
        encoding="utf-8",
    )


def write_checksums() -> None:
    all_sums = []
    for p in sorted(OUT.rglob("*")):
        if p.is_file() and p.name != "SHA256SUMS" and ".DS_Store" not in p.parts:
            all_sums.append(f"{sha256(p)}  {p.relative_to(OUT)}")
    (OUT / "SHA256SUMS").write_text("\n".join(all_sums) + "\n", encoding="utf-8")


def run_manuscript_packaging() -> int:
    """Refresh results/{figures,data,tables}."""
    TRACE.clear()
    PIC.mkdir(parents=True, exist_ok=True)
    TAB.mkdir(parents=True, exist_ok=True)
    DATA.mkdir(parents=True, exist_ok=True)

    export_conference_system_model()
    make_workflow()
    write_attr_data()
    write_role_data()
    write_fabric_data()
    write_longitudinal_data()
    write_baseline_data()
    write_system_baseline_data()
    copy_generated_figures()
    build_tables()
    write_checksums()

    if FIG.exists() and FIG.resolve() != PIC.resolve():
        shutil.rmtree(FIG, ignore_errors=True)

    n_pdf = len(list(PIC.glob("*.pdf")))
    print(json.dumps({"results": str(OUT), "n_pdf": n_pdf, "n_trace": len(TRACE)}, indent=2))
    return 0


def main() -> int:
    FIG.mkdir(parents=True, exist_ok=True)
    fig4_panels()
    fig5_panels()
    fig6_panels()
    fig7_panels()
    fig8_panels()
    fig9_panels()
    size_report = uniformize_tight_panel_groups()
    write_manifest()
    print(json.dumps({"n_panels": len(MANIFEST_ROWS), "out": str(FIG), "uniform_sizes": size_report}, indent=2))
    return run_manuscript_packaging()


if __name__ == "__main__":
    raise SystemExit(main())
