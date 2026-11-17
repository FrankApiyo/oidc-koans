# OIDC koans

Koans for OpenID Connect, in Python. Every file in `koans/` is a chain of
small tests with a blank in each one. Fill the blank, run the tests, and read
the next meditation. The chapters start with bytes and base64url, then build
JWS signatures by hand, run the authorization code flow, validate ID tokens
check by check, and end with step-up authentication and how real providers
report assurance.

The course is for people who use an OIDC library and want to know what it
does underneath. You should be able to read and write ordinary Python. No
earlier OAuth or OpenID Connect knowledge is assumed. By the end you should
be able to explain every check in an ID token validator and why it exists,
write one by hand, spot the classic client mistakes, and reason about
step-up the way the specs and providers describe it.

There are 215 koans in 22 chapters, plus a short chapter 00 on how the koans
work. They are planned as seven mornings of about two to three hours each.
Python 3.13 or newer is required.

## The toy world

Everything runs offline and gives the same result on every run. The `toy/`
package holds an OpenID Provider at `https://id.example`, a reference
client, a browser that keeps cookies, and an in-memory network that routes
requests between them. Nothing opens a socket, and a test guard refuses any
connection. Nothing reads the real clock. Time is a `Clock` that moves only
when a koan advances it. The keys are fixed test keys in `toy/keys/`.

You can read `toy/` whenever you like, but no koan asks you to edit it.

Each chapter opens with a short lesson that ends with "Read more" links to
the exact sections of the specs it teaches. Each security mistake is taught
in the chapter where its concept appears. Koans that check a refusal sit
beside koans that check the honest case is accepted, so a check that
refuses everything still fails. Five "spot the bug" koans show a short
validator with one real hole. You first write the input that gets through
it, then write the fix.

## Setup

```sh
git clone https://github.com/FrankApiyo/oidc-koans.git
cd oidc-koans
uv venv
uv pip install -r pyproject.toml
source .venv/bin/activate
pytest
```

Do not run `uv sync`. It writes a `uv.lock`, and some editors then run
tests through `uv run`.

## Editors

Any editor works, with the koans run from a terminal. Activate the venv
before you start the editor, so that its test runner and any REPL use
`.venv/bin/python`. Start the editor in the repo root, because the koans
import the blank from `conftest.py` there.

In Vim or Neovim, [vim-test](https://github.com/vim-test/vim-test) with its
default pytest runner runs the koans from the file you are in:

| vim-test       | Runs                             | In a terminal           |
| -------------- | -------------------------------- | ----------------------- |
| `:TestSuite`   | the whole course                 | `pytest`                |
| `:TestFile`    | the file you are in              | `pytest <file>`         |
| `:TestNearest` | the single koan under the cursor | `pytest <file>::<test>` |

Other editors have their own way to run the test under the cursor. The
terminal column shows the command any of them needs to run.

## The loop

Run `pytest`. It runs the koans in order and stops at the first one that
fails. The end of the output looks like this:

```
------------------------------- The master says --------------------------------
Meditate on koans/00_about_koans_test.py:31
    Replace __ with whatever makes the assertion true, save, run again.
0 of 215 koans answered.
```

Go to that line and read the meditation, which is the docstring just above
it. Replace the blank, save, and run again. When the last koan passes, the
footer says `Enlightenment`.

## Two kinds of blank

A plain `__` stands for a value. Replace it with the string, number, dict or
whatever else makes the assertion true.

A `__()` on a line of its own stands for code. It sits where a function body
should be:

```python
def bearer_header(token):
    __()
```

The meditation of the koan that calls the function says what it must do,
step by step. Replace the whole `__()` line with the body. Until you do,
calling the function raises `NotImplementedError`, and the footer points at
the blank itself rather than at the assertion:

```
------------------------------- The master says --------------------------------
Meditate on koans/00_about_koans_test.py:45
    Implement bearer_header above. 1. Replace the whole __() line with a return of the string "Bearer " followed by token.
3 of 215 koans answered.
```

## The seven mornings

Each morning keeps its chapters whole.

| Morning | Chapters | Koans |
| ------- | -------- | ----- |
| 1 | 00 How a koan works; 01 OAuth 2.0 roles, and why OpenID Connect sits on top; 02 Bytes, base64url and JSON; 03 JWS compact serialization and JWT claims | 35 |
| 2 | 04 HS256: MACs and shared secrets; 05 RS256 and ES256: public-key signatures; 06 JWK, JWKS and kid | 28 |
| 3 | 07 The authorization code flow, end to end; 08 redirect_uri exact matching and state; 09 nonce and PKCE | 27 |
| 4 | 10 The token endpoint and client authentication; 11 ID token validation, part 1: what kind, who signed, from whom, for whom; 12 ID token validation, part 2: time, nonce, acr and auth_time | 29 |
| 5 | 13 Access tokens, ID tokens, UserInfo, and matching sub; 14 Claims and scopes; 15 Discovery, issuer matching and mix-up defence; 16 JWKS key rotation | 38 |
| 6 | 17 sub vs email: choosing an account key; 18 Refresh tokens and rotation; 19 Sessions and logout | 30 |
| 7 | 20 Authentication context: acr, amr, auth_time, max_age, prompt, acr_values; 21 Step-up authentication (RFC 9470), and binding to the user; 22 Assurance in the wild: how providers report it differently | 28 |

Morning 5 has the most koans, but they are shorter than the ones in
mornings 6 and 7. If a morning runs long, stop at a chapter boundary.

## The lessons page

`lessons/index.html` gathers every chapter's lesson on one page, with
pictures of the roles, a JWS token, the code flow, the ID token checks, key
rotation and step-up. Open it in any browser. It loads nothing from the
network. Each picture is also a standalone file under `lessons/svg/`.

## Starting over

```sh
git checkout -- koans/
```

That restores every blank. For one chapter:

```sh
git checkout -- 'koans/05_*'
```

The same file under `solutions/` has the answers. Use it after a real
attempt, not instead of one. Never edit `solutions/` or `source/`.

## For maintainers

`source/` is the only copy you edit. A value answer is written as
`_a(value)`. A code answer is the run of lines between a `# >>> answer`
line and a `# <<<` line. `python tools/generate.py` writes two files for
each chapter. The one in `koans/` has each `_a(value)` replaced by `__` and
each answer block replaced by one `__()` line. The one in `solutions/` keeps
the answers and drops the marker lines. Commit all three directories
together.

The lessons page is built from the lesson that opens each file in
`source/`. The pictures are drawn in `tools/pictures_*.py`, and their
captions are in `tools/lessons.py`. After changing a lesson or a picture,
run these from the repo root:

```sh
python tools/diagrams.py
python tools/lessons.py
```

`toy/` is the reference implementation. Chapters import from `toy/`, never
from each other. When a koan has the learner write a function that `toy/`
also has, the two must agree.

The self-tests run with `pytest tests/`:

- `tests/test_koans.py` runs `koans/` and `solutions/` in subprocesses. It
  checks that every solution passes, that every unfilled koan fails rather
  than errors, that the generated files match `source/`, and that no course
  file reads the real clock or imports a network module. It also checks the
  lessons: their length, their "Read more" links, and that the lessons page
  and pictures are current and load nothing from the network.
- `tests/test_generate.py` checks the generator itself.
- `tests/test_parity_*.py` load each solved chapter function and check that
  it gives the same answer or refusal as its `toy/` counterpart.
- `tests/test_toy_*.py` test the `toy/` package directly.

Every "Read more" URL must appear in `tools/links.txt`, one per line. The
check is offline. Before adding a URL there, open it and confirm that the
page and its anchor exist.

## Licence

The code is under the Apache License 2.0 (see `LICENSE` and `NOTICE`). The
lesson text, comments that teach, pictures and README prose are under
Creative Commons Attribution 4.0 (see `LICENSE-lessons`). To credit this
work, write "OIDC koans by Frankline Apiyo" and link to this repository.
