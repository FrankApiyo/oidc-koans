"""Build lessons/index.html from the lesson that opens each chapter in source/.

A picture belongs to the chapter its file name starts with. Run from the repo
root, after tools/diagrams.py:

    python tools/lessons.py
"""

import ast
import re
from html import escape
from pathlib import Path

import diagrams

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "lessons" / "index.html"
READ_MORE = "Read more:"
MISTAKE = "A common mistake:"
TRAILING = ".,;:!?"

CAPTIONS = {
    "01_oauth_roles.svg": (
        "alice signs in at id.example, never at the client, and the client swaps the code for "
        "tokens on the back channel. Only the ID token says who signed in, and only to the client "
        "named in its aud."
    ),
    "03_jws_anatomy.svg": (
        "Three base64url segments joined by dots. The signature covers the first two exactly as "
        "sent, so anyone can decode a token, and only a key you already trust can vouch for it."
    ),
    "09_code_flow.svg": (
        "Where each secret travels. state goes out and back through the browser and must match a "
        "login bound in that browser's cookie; nonce comes back inside the ID token; the "
        "code_verifier never passes through the browser, only its S256 hash does."
    ),
    "11_id_token_checklist.svg": (
        "validate_id_token in the order toy.client runs it, with the reason each check raises. "
        "The order decides which reason a token with two defects gets."
    ),
    "16_key_rotation.svg": (
        "A rotation no client notices: publish k2, wait one cache lifetime, sign with k2, and "
        "retire k1 once its tokens have expired. The client fetches again for an unknown kid at "
        "most once per cooldown."
    ),
    "21_step_up.svg": (
        "max_age=0 forces a new sign-in. Its ID token counts only with this step-up's nonce, an "
        "auth_time after started_at (less leeway), the acr asked for, and the iss and sub of the "
        "user who asked."
    ),
    "21_step_up_challenge.svg": (
        "The challenge as chapter 21's API sends it, in the shape of RFC 9470 §3: the error code, "
        "then acr_values and max_age, which the client copies into its next authorization request."
    ),
}

STYLE = Path(__file__).with_name("lessons.css")


def _is_code(core: str) -> bool:
    has_letter = any(c.isalpha() for c in core)
    return "_" in core or "://" in core or ("=" in core and has_letter)


def _trim(token: str) -> tuple[str, str, str]:
    """(lead, core, tail): the punctuation of the sentence around a token, and the token."""
    start, end = 0, len(token)
    while start < end:
        core = token[start:end]
        if core[-1] in TRAILING:
            end -= 1
        elif core[-1] in ')"' and _unbalanced(core, core[-1]):
            end -= 1
        elif core[0] in '("' and _unbalanced(core, core[0]):
            start += 1
        elif core[0] == "(" and core[-1] == ")" and core.count("(") == 1:
            start, end = start + 1, end - 1
        else:
            break
    return token[:start], token[start:end], token[end:]


def _unbalanced(core: str, mark: str) -> bool:
    if mark == '"':
        return core.count('"') % 2 == 1
    return core.count("(") != core.count(")")


def _inline_token(token: str) -> str:
    lead, core, tail = _trim(token)
    if not (core and _is_code(core)):
        return escape(token, quote=False)
    lead, core, tail = (escape(part, quote=False) for part in (lead, core, tail))
    return f"{lead}<code>{core}</code>{tail}"


def inline(text: str) -> str:
    """Escape text for HTML, and set identifiers, parameters and URLs in code."""
    return "".join(_inline_token(token) for token in re.split(r"(\s+)", text))


def _blocks(text: str) -> list[list[str]]:
    blocks, current = [], []
    for line in text.splitlines():
        if line.strip():
            current = [*current, line]
        elif current:
            blocks, current = [*blocks, current], []
    return [*blocks, current] if current else blocks


def _list_items(lines: list[str]) -> list[str]:
    items = []
    for line in lines:
        if line.startswith("- "):
            items = [*items, line[2:].strip()]
        else:
            items = [*items[:-1], f"{items[-1]} {line.strip()}"]
    return items


def _block_html(lines: list[str]) -> str:
    if lines[0].startswith("- "):
        items = "".join(f"<li>{inline(item)}</li>" for item in _list_items(lines))
        return f"<ul>{items}</ul>"
    text = " ".join(line.strip() for line in lines)
    if text.startswith(MISTAKE):
        rest = text.removeprefix(MISTAKE).strip()
        return (
            f'<p class="mistake"><strong>{escape(MISTAKE, quote=False)}</strong> {inline(rest)}</p>'
        )
    return f"<p>{inline(text)}</p>"


def _links_html(urls: list[str]) -> str:
    if not urls:
        return ""
    items = "".join(
        f'<li><a href="{escape(url)}">{escape(url, quote=False)}</a></li>' for url in urls
    )
    return f'<p class="more">Read more</p>\n<ul class="links">{items}</ul>\n'


def _figure_html(name: str, svg) -> str:
    src = escape(f"svg/{name}")
    return (
        f'<figure><a href="{src}"><img src="{src}" alt="{escape(svg.label)}" '
        f'width="{svg.w}" height="{svg.h}" loading="lazy"></a>'
        f"<figcaption>{inline(CAPTIONS[name])}</figcaption></figure>\n"
    )


def chapters(root: Path = ROOT) -> list[tuple[str, str, str]]:
    """(number, short name, lesson) for every chapter in source/, in order."""
    found = []
    for path in sorted((root / "source").glob("*_test.py")):
        number, _, rest = path.name.removesuffix("_test.py").partition("_")
        lesson = ast.get_docstring(ast.parse(path.read_text())) or ""
        found = [*found, (number, rest.replace("_", " "), lesson)]
    return found


def section_html(number: str, lesson: str, figures) -> str:
    title, _, rest = lesson.partition("\n")
    body, _, more = rest.partition(READ_MORE)
    paragraphs = "\n".join(_block_html(block) for block in _blocks(body))
    pictures = "".join(_figure_html(name, svg) for name, svg in figures)
    urls = [line.strip() for line in more.splitlines() if line.strip()]
    return (
        f'<section id="c{number}">\n'
        f"<h2><small>{number}</small>{inline(title.strip().removesuffix('.'))}</h2>\n"
        f"{paragraphs}\n{pictures}{_links_html(urls)}</section>\n"
    )


def build(root: Path = ROOT) -> str:
    """The whole page, the same text on every run."""
    drawings = diagrams.drawings()
    found = chapters(root)
    nav = "".join(
        f'<a href="#c{number}">{number} {escape(name, quote=False)}</a>'
        for number, name, _ in found
    )
    sections = "\n".join(
        section_html(
            number, lesson, [(n, svg) for n, svg in drawings if n.startswith(f"{number}_")]
        )
        for number, _, lesson in found
    )
    return (
        "<!doctype html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>OIDC koans lessons</title>\n"
        f"<style>\n{STYLE.read_text()}</style>\n</head>\n<body>\n<main>\n"
        "<h1>OIDC koans lessons</h1>\n"
        '<p class="lead">The lesson from the top of each chapter, with a picture where a '
        "picture says it faster. Everything here works offline; only the Read more links leave "
        "the page.</p>\n"
        f"<nav>{nav}</nav>\n\n{sections}"
        "<footer>Built by <code>tools/lessons.py</code> from the lessons in <code>source/</code>; "
        "the pictures are plain SVG files under <code>lessons/svg/</code>, drawn by "
        "<code>tools/diagrams.py</code>. Lessons and pictures are under CC BY 4.0; see "
        "<code>LICENSE-lessons</code>.</footer>\n"
        "</main>\n</body>\n</html>\n"
    )


def main():
    PAGE.parent.mkdir(parents=True, exist_ok=True)
    PAGE.write_text(build())
    print("lessons/index.html")


if __name__ == "__main__":
    main()
