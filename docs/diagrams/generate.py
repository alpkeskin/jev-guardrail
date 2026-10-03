"""Generate Jev Guardrail README diagrams following diagram-design rules.

Writes light + dark self-contained HTML (inline SVG) sources. Every coordinate
is on the 4px grid; connectors are orthogonal; <=9 nodes, <=2 accents,
<=2 callouts per diagram.
"""
import sys
from pathlib import Path

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent
OUT.mkdir(parents=True, exist_ok=True)

# Brand skin derived from the logo (paper #f3f4f1, ink #0d0d0d).
SKINS = {
    "light": dict(
        paper="#f3f4f1", ink="#111111", muted="#55564f", soft="#85867f",
        accent="#eb6c36", accent_tint="rgba(235,108,54,0.08)", accent_tag="rgba(235,108,54,0.50)",
        accent_wm="rgba(235,108,54,0.10)",
        link="#2e5aa8", white="#ffffff", rgb="17,17,17",
    ),
    "dark": dict(
        paper="#161615", ink="#f3f4f1", muted="#b4b5ae", soft="#8e8f88",
        accent="#f08a59", accent_tint="rgba(240,138,89,0.10)", accent_tag="rgba(240,138,89,0.50)",
        accent_wm="rgba(240,138,89,0.12)",
        link="#6a95d8", white="#1f1f1d", rgb="243,244,241",
    ),
}

FONTS = ("https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1"
         "&family=Geist:wght@400;500;600&family=Geist+Mono:wght@400;500;600&display=swap")
SANS = "'Geist', sans-serif"
MONO = "'Geist Mono', monospace"
SERIF = "'Instrument Serif', serif"


def check_grid(*vals):
    for v in vals:
        assert v % 4 == 0, f"off-grid coordinate {v}"


class SVG:
    def __init__(self, s, slug):
        self.s, self.slug, self.parts = s, slug, []

    def c(self, alpha):  # ink at opacity
        return f"rgba({self.s['rgb']},{alpha})"

    def add(self, x):
        self.parts.append(x)

    # --- primitives -----------------------------------------------------
    def zone(self, x, y, w, h, label):
        check_grid(x, y, w, h)
        lw = int(len(label) * 7 * 0.62 + len(label) * 1 + 12) // 4 * 4 + 4
        cx = x + w // 2
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{self.c(0.02)}" '
                 f'stroke="{self.c(0.12)}" stroke-width="0.8"/>')
        self.add(f'<rect x="{cx - lw // 2}" y="{y + 4}" width="{lw}" height="12" rx="2" fill="{self.s["paper"]}"/>')
        self.add(f'<text x="{cx}" y="{y + 13}" fill="{self.c(0.45)}" font-size="7" font-family="{MONO}" '
                 f'text-anchor="middle" letter-spacing="0.14em">{label}</text>')

    def arrow(self, d, kind="muted", dashed=False):
        color = {"muted": self.s["muted"], "accent": self.s["accent"], "link": self.s["link"]}[kind]
        marker = {"muted": "arrow", "accent": "arrow-accent", "link": "arrow-link"}[kind]
        width = "1.4" if kind == "accent" else ("1" if dashed else "1.2")
        dash = ' stroke-dasharray="4,3"' if dashed else ""
        self.add(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{width}"{dash} '
                 f'marker-end="url(#{self.slug}-{marker})"/>')

    def label(self, cx, y, text, kind="muted", anchor="middle"):
        """Mask rect at y (top, h=12); text baseline y+9."""
        color = {"muted": self.s["muted"], "accent": self.s["accent"], "link": self.s["link"]}[kind]
        w = int(len(text) * 8 * 0.62 + len(text) * 0.5 + 8)
        w = (w + 3) // 4 * 4
        x = cx - w // 2 if anchor == "middle" else cx
        tx = cx if anchor == "middle" else cx + w // 2
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="12" rx="2" fill="{self.s["paper"]}"/>')
        self.add(f'<text x="{tx}" y="{y + 9}" fill="{color}" font-size="8" font-family="{MONO}" '
                 f'text-anchor="middle" letter-spacing="0.06em">{text}</text>')

    def _style(self, kind):
        s = self.s
        return {
            "focal": (s["accent_tint"], s["accent"], "", s["accent_tag"], s["accent"]),
            "backend": (s["white"], s["ink"], "", self.c(0.40), s["ink"]),
            "store": (self.c(0.05), s["muted"], "", self.c(0.40), s["muted"]),
            "external": (self.c(0.03), self.c(0.30), "", self.c(0.22), s["soft"]),
            "input": (self.c(0.06), s["soft"], "", self.c(0.30), s["soft"]),
            "optional": (self.c(0.02), self.c(0.30), ' stroke-dasharray="4,3"', self.c(0.22), s["soft"]),
        }[kind]

    def node(self, x, y, w, h, kind, tag, name, sub):
        check_grid(x, y, w, h)
        fill, stroke, dash, tagstroke, tagtext = self._style(kind)
        cx, cy = x + w // 2, y + h // 2
        tw = (len(tag) * 7 * 0.62 + 10)
        tw = int((tw + 3) // 4 * 4)
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="{self.s["paper"]}"/>')
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="{fill}" stroke="{stroke}" '
                 f'stroke-width="1"{dash}/>')
        self.add(f'<rect x="{x + 8}" y="{y + 8}" width="{tw}" height="12" rx="2" fill="none" '
                 f'stroke="{tagstroke}" stroke-width="0.8"/>')
        self.add(f'<text x="{x + 8 + tw / 2:g}" y="{y + 17}" fill="{tagtext}" font-size="7" font-family="{MONO}" '
                 f'text-anchor="middle" letter-spacing="0.08em">{tag}</text>')
        self.add(f'<text x="{cx}" y="{cy + 4}" fill="{self.s["ink"]}" font-size="12" font-weight="600" '
                 f'font-family="{SANS}" text-anchor="middle">{name}</text>')
        self.add(f'<text x="{cx}" y="{cy + 20}" fill="{self.s["muted"]}" font-size="9" font-family="{MONO}" '
                 f'text-anchor="middle">{sub}</text>')

    def step(self, x, y, w, h, name, sub):
        check_grid(x, y, w, h)
        cx, cy = x + w // 2, y + h // 2
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="{self.s["white"]}" '
                 f'stroke="{self.s["ink"]}" stroke-width="1"/>')
        self.add(f'<text x="{cx}" y="{cy - 2}" fill="{self.s["ink"]}" font-size="12" font-weight="600" '
                 f'font-family="{SANS}" text-anchor="middle">{name}</text>')
        self.add(f'<text x="{cx}" y="{cy + 14}" fill="{self.s["muted"]}" font-size="9" font-family="{MONO}" '
                 f'text-anchor="middle">{sub}</text>')

    def oval(self, x, y, w, h, name, sub, kind="plain"):
        check_grid(x, y, w, h)
        cx, cy = x + w // 2, y + h // 2
        fill, stroke = self.s["white"], self.s["ink"]
        if kind == "muted":
            fill, stroke = self.c(0.04), self.s["muted"]
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{h // 2}" fill="{fill}" '
                 f'stroke="{stroke}" stroke-width="1"/>')
        self.add(f'<text x="{cx}" y="{cy - 1}" fill="{self.s["ink"]}" font-size="12" font-weight="600" '
                 f'font-family="{SANS}" text-anchor="middle">{name}</text>')
        self.add(f'<text x="{cx}" y="{cy + 14}" fill="{self.s["muted"]}" font-size="9" font-family="{MONO}" '
                 f'text-anchor="middle">{sub}</text>')

    def diamond(self, cx, cy, hw, hh, text, focal=False):
        check_grid(cx, cy, hw, hh)
        fill, stroke = (self.s["accent_tint"], self.s["accent"]) if focal else (self.s["white"], self.s["ink"])
        pts = f"{cx},{cy - hh} {cx + hw},{cy} {cx},{cy + hh} {cx - hw},{cy}"
        self.add(f'<polygon points="{pts}" fill="{self.s["paper"]}"/>')
        self.add(f'<polygon points="{pts}" fill="{fill}" stroke="{stroke}" stroke-width="1"/>')
        self.add(f'<text x="{cx}" y="{cy + 4}" fill="{self.s["ink"]}" font-size="12" font-weight="600" '
                 f'font-family="{SANS}" text-anchor="middle">{text}</text>')

    def callout(self, tx, ty, text, anchor, leader, dot):
        self.add(f'<text x="{tx}" y="{ty}" fill="{self.s["ink"]}" font-size="14" font-style="italic" '
                 f'font-family="{SERIF}" text-anchor="{anchor}">{text}</text>')
        self.add(f'<path d="{leader}" fill="none" stroke="{self.c(0.40)}" stroke-width="1" stroke-dasharray="4,3"/>')
        self.add(f'<circle cx="{dot[0]}" cy="{dot[1]}" r="2" fill="{self.s["ink"]}"/>')

    def legend(self, y, width, items):
        self.add(f'<line x1="40" y1="{y}" x2="{width - 40}" y2="{y}" stroke="{self.c(0.10)}" stroke-width="0.8"/>')
        self.add(f'<text x="40" y="{y + 16}" fill="{self.s["muted"]}" font-size="8" font-family="{MONO}" '
                 f'letter-spacing="0.18em">LEGEND</text>')
        x = 40
        iy = y + 28
        for kind, text in items:
            s = self.s
            if kind.startswith("arrow"):
                k = kind.split(":")[1]
                color = {"muted": s["muted"], "accent": s["accent"], "link": s["link"], "dash": s["muted"]}[k]
                marker = {"muted": "arrow", "accent": "arrow-accent", "link": "arrow-link", "dash": "arrow"}[k]
                dash = ' stroke-dasharray="4,3"' if k == "dash" else ""
                self.add(f'<line x1="{x}" y1="{iy + 6}" x2="{x + 28}" y2="{iy + 6}" stroke="{color}" '
                         f'stroke-width="1.2"{dash} marker-end="url(#{self.slug}-{marker})"/>')
                tx = x + 36
            elif kind == "oval":
                self.add(f'<rect x="{x}" y="{iy}" width="20" height="12" rx="6" fill="{s["white"]}" '
                         f'stroke="{s["ink"]}" stroke-width="1"/>')
                tx = x + 28
            elif kind == "diamond":
                self.add(f'<polygon points="{x + 10},{iy} {x + 22},{iy + 6} {x + 10},{iy + 12} {x - 2},{iy + 6}" '
                         f'fill="{s["white"]}" stroke="{s["ink"]}" stroke-width="1"/>')
                tx = x + 28
            elif kind == "diamond-focal":
                self.add(f'<polygon points="{x + 10},{iy} {x + 22},{iy + 6} {x + 10},{iy + 12} {x - 2},{iy + 6}" '
                         f'fill="{s["accent_tint"]}" stroke="{s["accent"]}" stroke-width="1"/>')
                tx = x + 28
            else:
                fill, stroke, dash, _, _ = self._style(kind) if kind != "step" else (s["white"], s["ink"], "", 0, 0)
                self.add(f'<rect x="{x}" y="{iy}" width="16" height="12" rx="2" fill="{fill}" '
                         f'stroke="{stroke}" stroke-width="1"{dash}/>')
                tx = x + 24
            self.add(f'<text x="{tx}" y="{iy + 9}" fill="{s["muted"]}" font-size="8.5" font-family="{SANS}">{text}</text>')
            x = tx + int(len(text) * 8.5 * 0.56) + 28

    def render(self, w, h, title, desc, top=0):
        s = self.s
        markers = "".join(
            f'<marker id="{self.slug}-{mid}" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">'
            f'<polygon points="0 0, 8 3, 0 6" fill="{col}"/></marker>'
            for mid, col in (("arrow", s["muted"]), ("arrow-accent", s["accent"]), ("arrow-link", s["link"])))
        body = "\n    ".join(self.parts)
        return (f'<svg viewBox="0 {top} {w} {h - top}" xmlns="http://www.w3.org/2000/svg" role="img" '
                f'aria-labelledby="{self.slug}-title {self.slug}-desc">\n'
                f'    <title id="{self.slug}-title">{title}</title>\n'
                f'    <desc id="{self.slug}-desc">{desc}</desc>\n'
                f'    <defs>{markers}</defs>\n'
                f'    <rect x="0" y="{top}" width="{w}" height="{h - top}" fill="{s["paper"]}"/>\n    {body}\n</svg>')


def page(svg, s, eyebrow, h1, title):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <!-- Generated with diagram-design conventions (github.com/cathrynlavery/diagram-design). -->
  <link href="{FONTS.replace('&', '&amp;')}" rel="stylesheet">
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Geist', system-ui, sans-serif; background: {s['paper']}; color: {s['ink']};
           min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 3rem 2rem; }}
    .frame {{ width: 1000px; }}
    .eyebrow {{ font-family: 'Geist Mono', monospace; font-size: 0.66rem; font-weight: 500; letter-spacing: 0.18em;
               text-transform: uppercase; color: {s['muted']}; margin-bottom: 0.5rem; }}
    h1 {{ font-family: 'Instrument Serif', serif; font-size: 2rem; font-weight: 400; letter-spacing: -0.02em;
         line-height: 1.15; margin-bottom: 1.5rem; }}
    svg {{ width: 1000px; display: block; }}
  </style>
</head>
<body>
  <div class="frame">
    <p class="eyebrow">{eyebrow}</p>
    <h1>{h1}</h1>
    {svg}
  </div>
</body>
</html>
"""


def architecture(variant):
    slug = "architecture" + ("-dark" if variant == "dark" else "")
    g = SVG(SKINS[variant], slug)
    # Arrows before nodes.
    g.arrow("M 200,200 H 400", "accent")                                        # app -> guardrail
    g.arrow("M 400,216 H 200", dashed=True)                                     # judgment back
    g.arrow("M 120,176 V 136 Q 120,128 128,128 H 872 Q 880,128 880,136 V 176")  # app -> llm, only if passed
    g.arrow("M 440,336 V 240")                                                  # policies -> guardrail
    g.arrow("M 600,240 V 336", "link")                                          # guardrail -> jev
    g.label(300, 180, "PROMPT · RESPONSE", "accent")
    g.label(300, 224, "JUDGMENT")
    g.label(704, 108, "ONLY IF PASSED")
    g.label(400, 276, "RESOLVE")
    g.label(612, 276, "EVALUATE", "link", anchor="start")
    # Callouts in the bottom margins.
    g.callout(40, 336, "Your app owns enforcement.", "start", "M 112,320 Q 120,292 120,244", (120, 244))
    g.callout(960, 336, "Never calls the LLM itself.", "end", "M 840,320 Q 760,300 612,232", (612, 232))
    # Nodes.
    g.node(40, 176, 160, 64, "backend", "APP", "Your application", "app · agent · gateway")
    g.node(400, 176, 208, 64, "focal", "API", "Jev Guardrail", "POST /v1/guard")
    g.node(800, 176, 160, 64, "optional", "LLM", "LLM provider", "any model")
    g.node(368, 336, 144, 64, "store", "YAML", "Policies", "per client")
    g.node(528, 336, 144, 64, "external", "EXT", "Jev", "detection")
    g.legend(432, 1000, [("focal", "Decision service"), ("backend", "Caller"), ("store", "Config"),
                         ("external", "Dependency"), ("optional", "Called by your app"),
                         ("arrow:accent", "Guard check"), ("arrow:link", "API call"), ("arrow:dash", "Return")])
    svg = g.render(1000, 488, "Where Jev Guardrail sits",
                   "Architecture diagram: an application sends prompts and responses to Jev Guardrail, which resolves "
                   "a policy, asks Jev for scores and returns a judgment; the application calls the LLM provider only "
                   "if the content passed.", top=80)
    return slug, page(svg, SKINS[variant], "Architecture · Jev Guardrail", "Where Jev Guardrail sits", "Jev Guardrail · Architecture")


def flow(variant):
    slug = "decision-flow" + ("-dark" if variant == "dark" else "")
    g = SVG(SKINS[variant], slug)
    # Spine arrows.
    g.arrow("M 500,80 V 112")
    g.arrow("M 500,168 V 200")
    g.arrow("M 500,280 V 316")
    g.arrow("M 500,372 V 404")
    g.arrow("M 500,484 V 520")
    # Failure exits to FAILED.
    g.arrow("M 596,240 H 808 Q 816,240 816,248 V 316")
    g.arrow("M 596,444 H 808 Q 816,444 816,436 V 368")
    # Policy decision exits.
    g.arrow("M 612,560 H 736", "accent")
    g.arrow("M 500,600 V 640")
    g.label(512, 292, "YES", anchor="start")
    g.label(512, 496, "YES", anchor="start")
    g.label(700, 220, "NO")
    g.label(700, 424, "NO")
    g.label(676, 540, "YES", "accent")
    g.label(512, 612, "NO", anchor="start")
    # Callouts.
    g.callout(952, 136, "Errors are FAILED, never BLOCKED.", "end", "M 876,144 Q 904,228 856,312", (856, 316))
    g.callout(64, 668, "Review matches are reported, not blocked.", "start", "M 292,664 H 404", (408, 664))
    # Nodes.
    g.oval(412, 32, 176, 48, "Request", "POST /v1/guard")
    g.step(412, 112, 176, 56, "Resolve policy", "X-Client-ID · default")
    g.diamond(500, 240, 96, 40, "Valid request?")
    g.step(412, 316, 176, 56, "Evaluate with Jev", "breaker · concurrency limit")
    g.diamond(500, 444, 96, 40, "Jev responded?")
    g.diamond(500, 560, 112, 40, "Block rule matched?", focal=True)
    g.oval(736, 316, 160, 52, "FAILED", "400 · 502 · 503", "muted")
    g.oval(736, 536, 160, 48, "BLOCKED", "HTTP 200")
    g.oval(412, 640, 176, 48, "PASSED", "HTTP 200")
    g.legend(712, 1000, [("oval", "Start / judgment"), ("step", "Step"), ("diamond", "Decision"),
                         ("diamond-focal", "Policy decision"), ("arrow:muted", "Flow"), ("arrow:accent", "Block path")])
    svg = g.render(1000, 768, "How a request is judged",
                   "Flowchart: a guard request is matched to a policy and validated, then evaluated by Jev; invalid "
                   "input or Jev errors end as FAILED, a matched block rule ends as BLOCKED, otherwise PASSED.")
    return slug, page(svg, SKINS[variant], "Flowchart · Jev Guardrail", "How a request is judged", "Jev Guardrail · Decision flow")


for build in (architecture, flow):
    for variant in ("light", "dark"):
        slug, html = build(variant)
        (OUT / f"{slug}.html").write_text(html)
        print("wrote", OUT / f"{slug}.html")
