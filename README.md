# OIDC koans

Koans for OpenID Connect, in Python. You fill in `__` blanks and the tests turn green, from base64url and JWTs up to the code flow, ID token validation and step-up authentication. It runs offline against a toy provider that lives in this repo.

## Setup

```
git clone https://github.com/FrankApiyo/oidc-koans.git
cd oidc-koans
uv venv
uv pip install -r pyproject.toml
source .venv/bin/activate
pytest
```

Do not run `uv sync`: it writes a `uv.lock`, and some editors then run tests through `uv run`.

## Licence

The code is under the Apache License 2.0 (see `LICENSE` and `NOTICE`). The lesson text, comments that teach, pictures and README prose are under Creative Commons Attribution 4.0 (see `LICENSE-lessons`). To credit this work, write "OIDC koans by Frankline Apiyo" and link to this repository.
