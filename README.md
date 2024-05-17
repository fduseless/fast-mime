# Fast MIME

Support Rails/[Marcel](https://github.com/rails/marcel) style MIME for Python.

It uses Apache Tike's rule.

## Install

```bash
pip install fast-mime
```

## Usage

```python
from fast_mime import MIME
with open("a.pdf") as fi:
    mime = MIME(file=fi, name="a.pdf", declared_type="application/pdf", extension=".pdf")
    # all parameters are optional
```
