from pathlib import Path
from fast_mime import MIME
import os


def content_type_testcases(type: str = "name"):
    dir = os.path.join(os.path.dirname(__file__), "fixtures", type)
    for first in os.listdir(dir):
        first_dir = os.path.join(dir, first)
        for second in os.listdir(first_dir):
            second_dir = os.path.join(first_dir, second)
            if os.path.isdir(second_dir):
                for name in os.listdir(second_dir):
                    yield os.path.join(second_dir, name), name, f"{first}/{second}"
            else:
                yield second_dir, second, first


def files(name: str) -> str:
    return os.path.join(os.path.dirname(__file__), "fixtures", "name", name)


def test_declare():
    assert "text/html" == MIME(name="file.txt", declared_type="text/html")
    assert "text/plain" == MIME(
        name="file.txt", declared_type="application/octet-stream"
    )
    assert "application/octet-stream" == MIME(declared_type=None)
    assert "application/octet-stream" == MIME(declared_type="")
    assert "application/octet-stream" == MIME(declared_type="unrecognised")


def test_extension():
    assert "application/pdf" == MIME(extension="PDF")
    assert "application/pdf" == MIME(extension=".PDF")
    assert "application/pdf" == MIME(extension="pdf")
    assert "application/pdf" == MIME(extension=".pdf")


def test_extension2():
    for path, _, content_type in content_type_testcases():
        extension = Path(path).suffix
        assert content_type, MIME(extension=extension)


def test_illustrator():
    file = files("application/illustrator/illustrator.ai")
    assert "application/illustrator" == MIME(
        file, name="illustrator.ai", declared_type="application/postscript"
    )
    assert "application/illustrator" == MIME(
        file, name="illustrator.ai", declared_type="application/pdf"
    )
    assert "application/illustrator" == MIME(
        file, name="illustrator.ai", declared_type="application/octet-stream"
    )


def test_magic_and_declared_type():
    for file, _, content_type in content_type_testcases():
        assert content_type == MIME(file, declared_type=content_type)


def test_magic_and_name():
    for file, name, content_type in content_type_testcases():
        assert content_type == MIME(file, name=name)


def test_magic():
    for file, name, content_type in content_type_testcases("magic"):
        assert file and content_type == MIME(file)
