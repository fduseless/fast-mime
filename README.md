# Fast MIME

Support Rails/[Marcel](https://github.com/rails/marcel) style MIME for Python.

It uses Apache Tike's rule.

It's customizable.

## Install

```bash
pip install fast-mime
```

## Usage

### Detect MIME

```python
from fast_mime import MIME
with open("a.pdf", "rb") as fi:
    # detect an opened file
    mime = MIME(fi, name="a.pdf", declared_type="application/pdf", extension=".pdf")
    # all parameters are optional

# detect an unopenned file
mime = MIME("a.pdf", declared_type="application/pdf", extension=".pdf")

# detect without any hint
mime = MIME("a")
```

### Customize MIME rules

```python
from fast_mime import Mime

# define your own mime rule
MIME = Mime.from_xmls(your_rule_file_name)
```

### Patch MIME

```python

class MyMime(Mime):
    def _patch(self):
        super()._patch()
        ...

```
