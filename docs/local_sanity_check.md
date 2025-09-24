# Local sanity check

Make sure twine is installed (´pipenv install --dev´)

```bash
pipenv run python -m build
pipenv run twine check dist/*
```
