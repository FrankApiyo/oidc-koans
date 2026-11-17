"""Write the lesson pictures to lessons/svg/ as standalone coloured SVG files.

The drawings live in pictures_*.py beside this file. Run from the repo root:

    python tools/diagrams.py
"""

from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "lessons" / "svg"

BG = "#fafaf9"
INK = "#1f2937"
MUTED = "#6b7280"
BLUE = "#2563eb"
ORANGE = "#ea580c"
GREEN = "#16a34a"
RED = "#dc2626"
PURPLE = "#7c3aed"
FILL_BLUE = "#dbeafe"
FILL_ORANGE = "#ffedd5"
FILL_GREEN = "#dcfce7"
FILL_YELLOW = "#fef3c7"
FILL_GREY = "#e5e7eb"
FILL_PURPLE = "#ede9fe"
FILL_RED = "#fee2e2"

SANS = "ui-sans-serif, system-ui, sans-serif"
MONO = "ui-monospace, Menlo, Consolas, monospace"

COLORS = {
    "ink": INK,
    "muted": MUTED,
    "blue": BLUE,
    "orange": ORANGE,
    "green": GREEN,
    "red": RED,
    "purple": PURPLE,
}


def _number(value) -> str:
    """Coordinates print the same on every run: whole numbers bare, others to two places."""
    return str(int(value)) if float(value).is_integer() else f"{value:.2f}"


class Svg:
    def __init__(self, width, height, label):
        self.w = width
        self.h = height
        self.label = label
        self.parts = ()

    def _add(self, part):
        self.parts = (*self.parts, part)

    def rect(self, x, y, w, h, fill="none", stroke=INK, rx=4, width=1.5, dashed=False):
        dash = ' stroke-dasharray="5 4"' if dashed else ""
        n = _number
        self._add(
            f'<rect x="{n(x)}" y="{n(y)}" width="{n(w)}" height="{n(h)}" rx="{rx}" fill="{fill}" '
            f'stroke="{stroke}" stroke-width="{width}"{dash}/>'
        )

    def circle(self, cx, cy, r, fill="none", stroke=INK, width=1.5):
        n = _number
        self._add(
            f'<circle cx="{n(cx)}" cy="{n(cy)}" r="{n(r)}" fill="{fill}" stroke="{stroke}" '
            f'stroke-width="{width}"/>'
        )

    def text(
        self, x, y, s, size=13, anchor="middle", fill=INK, weight="normal", mono=False, italic=False
    ):
        self.spans(
            x, y, ((s, fill),), size=size, anchor=anchor, weight=weight, mono=mono, italic=italic
        )

    def spans(
        self, x, y, pieces, size=13, anchor="middle", weight="normal", mono=False, italic=False
    ):
        """One line of text whose pieces, given as (text, colour), each keep their own colour."""
        family = MONO if mono else SANS
        style = ' font-style="italic"' if italic else ""
        body = "".join(
            (
                escape(piece, quote=False)
                if color == INK
                else f'<tspan fill="{color}">{escape(piece, quote=False)}</tspan>'
            )
            for piece, color in pieces
        )
        self._add(
            f'<text x="{_number(x)}" y="{_number(y)}" font-family="{family}" font-size="{size}" '
            f'text-anchor="{anchor}" fill="{INK}" font-weight="{weight}"{style} '
            f'xml:space="preserve">{body}</text>'
        )

    def line(self, x1, y1, x2, y2, stroke=INK, arrow=True, dashed=False, width=1.5):
        name = next(k for k, v in COLORS.items() if v == stroke)
        marker = f' marker-end="url(#arrow-{name})"' if arrow else ""
        dash = ' stroke-dasharray="5 4"' if dashed else ""
        n = _number
        self._add(
            f'<line x1="{n(x1)}" y1="{n(y1)}" x2="{n(x2)}" y2="{n(y2)}" stroke="{stroke}" '
            f'stroke-width="{width}"{dash}{marker}/>'
        )

    def box(self, x, y, w, h, label, fill="none", stroke=INK, mono=True, size=13, sub=None):
        self.rect(x, y, w, h, fill=fill, stroke=stroke)
        dy = -4 if sub else 5
        self.text(x + w / 2, y + h / 2 + dy, label, size=size, mono=mono)
        if sub:
            self.text(x + w / 2, y + h / 2 + 12, sub, size=10, fill=MUTED)

    def lifeline(self, x, top, bottom, label, sub):
        """A sequence-diagram participant: a named box with a dashed line down from it."""
        self.box(x - 95, top, 190, 44, label, fill=FILL_GREY, sub=sub, size=12)
        self.line(x, top + 44, x, bottom, stroke=MUTED, arrow=False, dashed=True, width=1)

    def message(self, x1, x2, y, pieces, size=11, stroke=INK):
        """An arrow from one lifeline to another, its label just above it."""
        gap = 4 if x2 > x1 else -4
        self.line(x1 + gap, y, x2 - gap, y, stroke=stroke)
        self.spans((x1 + x2) / 2, y - 6, pieces, size=size, mono=True)

    def note(self, x, y, w, lines, size=11, fill=FILL_YELLOW):
        """A box of one or more lines, each a sequence of (text, colour) pieces."""
        self.rect(x, y, w, 10 + 15 * len(lines), fill=fill, stroke=MUTED, width=1)
        for row, pieces in enumerate(lines):
            self.spans(x + 8, y + 18 + 15 * row, pieces, size=size, anchor="start", mono=True)

    def markup(self):
        defs = "".join(
            f'<marker id="arrow-{k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
            f'markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" '
            f'fill="{v}"/></marker>'
            for k, v in COLORS.items()
        )
        body = "\n".join(self.parts)
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" '
            f'width="{self.w}" height="{self.h}" role="img" aria-label="{escape(self.label)}">\n'
            f"<defs>{defs}</defs>\n"
            f'<rect width="{self.w}" height="{self.h}" fill="{BG}"/>\n'
            f"{body}\n</svg>\n"
        )


def drawings():
    """Every picture as (file name, Svg), in the order the lessons use them."""
    import pictures_flows
    import pictures_tokens

    return (
        ("01_oauth_roles.svg", pictures_tokens.roles()),
        ("03_jws_anatomy.svg", pictures_tokens.jws_anatomy()),
        ("09_code_flow.svg", pictures_flows.code_flow()),
        ("11_id_token_checklist.svg", pictures_tokens.id_token_checklist()),
        ("16_key_rotation.svg", pictures_tokens.key_rotation()),
        ("21_step_up.svg", pictures_flows.step_up()),
        ("21_step_up_challenge.svg", pictures_flows.step_up_challenge()),
    )


def render() -> dict[str, str]:
    """{file name: SVG text} for every picture."""
    return {name: svg.markup() for name, svg in drawings()}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, text in render().items():
        (OUT / name).write_text(text)
        print(f"lessons/svg/{name}")


if __name__ == "__main__":
    main()
