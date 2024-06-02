from contextlib import contextmanager
from dataclasses import dataclass
from functools import cached_property
import json
import os
from pathlib import Path
import re
from typing import IO, Any, Dict, Generator, List, Tuple
import xml.etree.ElementTree as ET

from typing import TypeVar
import logging

logger = logging.getLogger("fast-mime")

CONTENT_TYPE_SPLITTER = re.compile(r"[;,\s]")
GLOB_PAT = re.compile(r"^\*\.([^\[\]]+)$")
MASK_PAT = re.compile(r"^0x(FF|00)*$")
VALUE_PAT = re.compile(r"^0x([0-9a-fA-F]+)$")
MASK_SPLIT = re.compile("(?:FF)+")

MatchPatch = Tuple[int, str] | Tuple[int, str, List["MatchPatch"]]
MagicPatch = List[MatchPatch]
Segment = Tuple[bytes, int, int] | Tuple[bytes, bytes, int]

T = TypeVar("T")


def _str2int(e: str) -> int:
    if e.startswith("0") and not e.startswith("0x"):
        return int(e[1:], 8)
    return int(e, 0)


def _first(e: List[T]) -> T | None:
    if len(e) == 0:
        return None
    return e[0]


def _dedup(lst: List[T]) -> List[T]:
    dedup = set[T]()
    ret: List[T] = []
    for e in lst:
        if e not in dedup:
            ret.append(e)
            dedup.add(e)
    return ret


@dataclass
class Glob:
    pattern: str

    @classmethod
    def from_xml(cls, el: ET.Element) -> "Glob":
        assert el.tag == "glob"
        pattern = el.get("pattern")
        assert pattern is not None
        return Glob(pattern=pattern)


@dataclass
class Match:
    value: str
    type: str
    offset: Tuple[int, int] | int
    children: List["Match"]
    mask: str | None
    min_should_match: int = 1

    @property
    def segments(self) -> List[Segment]:
        return self._segments

    @property
    def bytes_start(self) -> int:
        return self._bytes_start

    @property
    def bytes_end(self) -> int:
        return self._bytes_end

    @property
    def valid(self) -> bool:
        return len(self._segments) > 0 or self.min_should_match > 1

    @classmethod
    def from_xml(cls, el: ET.Element) -> "Match":
        assert el.tag == "match"
        value = el.get("value")
        type = el.get("type") or "string"
        offset = el.get("offset") or "0"
        mask = el.get("mask")
        min_should_match = el.get("minShouldMatch")

        assert value is not None or min_should_match is not None

        offset_ = [int(t) for t in offset.split(":")]

        value = value or ""

        if not (value.startswith("0x") and value.startswith("\\x")):
            value = (
                (value or "")
                .replace("\\ ", " ")
                .encode("raw_unicode_escape")
                .decode("unicode_escape")
            )

        return Match(
            value=value,
            type=type,
            offset=(
                (offset_[0], offset_[1] + offset_[0])
                if len(offset_) > 1
                else offset_[0]
            ),
            children=[
                m
                for m in [Match.from_xml(child) for child in el if child.tag == "match"]
                if m.valid
            ],
            mask=mask,
            min_should_match=int(min_should_match or "1"),
        )

    def __post_init__(self):
        segments: List[Segment] = []
        self._segments = segments
        self._bytes_end = 0

        if self.min_should_match != 1:
            return

        if self.type == "string" or self.type == "stringignorecase":
            value = self.value
            if m := VALUE_PAT.match(value):
                txt = m.group(1)
                bytes_value = bytes.fromhex(txt)
            elif value.startswith("\\x"):
                txt = value.replace("\\x", "")
                bytes_value = bytes.fromhex(txt)
            else:
                bytes_value = bytes(value, encoding="raw_unicode_escape")
            if self.mask:
                if not MASK_PAT.match(self.mask):
                    segments.append(
                        (
                            bytes_value,
                            bytes(self.mask, encoding="raw_unicode_escape"),
                            len(bytes_value),
                        )
                    )
                else:
                    for match_ in MASK_SPLIT.finditer(self.mask):
                        start, end = match_.span()
                        start = start // 2 - 1
                        end = end // 2 - 1
                        segments.append((bytes_value[start:end], start, end))
            else:
                segments.append((bytes_value, 0, len(bytes_value)))
        elif self.type == "big16":
            value = _str2int(self.value)
            bytes_value = value.to_bytes(2, "big")
            segments.append((bytes_value, 0, len(bytes_value)))
        elif self.type == "big32":
            value = _str2int(self.value)
            bytes_value = value.to_bytes(4, "big")
            segments.append((bytes_value, 0, len(bytes_value)))
        elif self.type == "little16":
            value = _str2int(self.value)
            bytes_value = value.to_bytes(2, "little")
            segments.append((bytes_value, 0, len(bytes_value)))
        elif self.type == "little32":
            value = _str2int(self.value)
            bytes_value = value.to_bytes(4, "little")
            segments.append((bytes_value, 0, len(bytes_value)))
        elif self.type == "host16":
            value = _str2int(self.value)
            bytes_value = value.to_bytes(2, "little")
            segments.append((bytes_value, 0, len(bytes_value)))
        elif self.type == "host32":
            value = _str2int(self.value)
            bytes_value = value.to_bytes(4, "little")
            segments.append((bytes_value, 0, len(bytes_value)))
        elif self.type == "byte":
            value = _str2int(self.value)
            bytes_value = value.to_bytes(1)
            segments.append((bytes_value, 0, len(bytes_value)))

        if isinstance(self.offset, Tuple):
            self._bytes_start = self.offset[0]
            self._bytes_end = self.offset[-1]
        else:
            self._bytes_start = self.offset
            self._bytes_end = (
                max([size for _, _, size in segments], default=0) + self.offset
            )


@dataclass
class Magic:
    matchs: List[Match]
    priority: int = 50

    @property
    def bytes_end(self) -> int:
        return self._bytes_end

    @classmethod
    def from_xml(cls, el: ET.Element) -> "Magic":
        assert el.tag == "magic"
        priority = el.get("priority") or "50"
        return Magic(
            priority=int(priority),
            matchs=[
                m
                for m in [Match.from_xml(child) for child in el if child.tag == "match"]
                if m.valid
            ],
        )

    def __post_init__(self):
        self._bytes_end = max([match.bytes_end for match in self.matchs], default=0)


@dataclass
class Alias:
    type: str


@dataclass
class MimeType:
    type: str
    magics: List[Magic]
    acronym: str | None
    alias: List[str]
    globs: List[Glob]
    parents: List[str]
    comment: str | None

    @classmethod
    def _parse_alias(cls, el: ET.Element) -> str:
        assert el.tag == "alias"
        type = el.get("type")
        assert type is not None
        return type

    @classmethod
    def _parse_acronym(cls, el: ET.Element) -> str:
        assert el.tag == "acronym" and el.text
        return el.text

    @classmethod
    def _parse_parent(cls, el: ET.Element) -> str:
        assert el.tag == "sub-class-of"
        type = el.get("type")
        assert type
        return type

    @classmethod
    def _parse_comment(cls, el: ET.Element) -> str:
        assert el.tag == "_comment"
        return el.text or ""

    @classmethod
    def from_xml(cls, el: ET.Element) -> "MimeType":
        assert el.tag == "mime-type"
        type = el.get("type")
        assert type is not None
        return MimeType(
            type=type,
            magics=[Magic.from_xml(child) for child in el if child.tag == "magic"],
            acronym=_first(
                [cls._parse_acronym(child) for child in el if child.tag == "acronym"]
            ),
            alias=[cls._parse_alias(child) for child in el if child.tag == "alias"],
            globs=[Glob.from_xml(child) for child in el if child.tag == "glob"],
            parents=[
                cls._parse_parent(child) for child in el if child.tag == "sub-class-of"
            ],
            comment=_first(
                [cls._parse_comment(child) for child in el if child.tag == "_comment"]
            ),
        )


@dataclass
class Mime:
    types: List[MimeType]

    @property
    def bytes_end(self) -> int:
        return self._bytes_end

    @classmethod
    def default_mime_files(cls) -> List[str | Path]:
        return [
            os.path.join(os.path.dirname(__file__), "data", name)
            for name in ["custom.xml", "tika.xml"]
        ]

    @cached_property
    def _common_types(self) -> List[str]:
        return [
            "image/jpeg",  # .jpg
            "image/png",  # .png
            "image/gif",  # .gif
            "image/tiff",  # .tiff
            "image/bmp",  # .bmp
            "image/vnd.adobe.photoshop",  # .psd
            "image/webp",  # .webp
            "text/html",  # .html
            "image/svg+xml",  # .svg
            "video/x-msvideo",  # .avi
            "video/x-ms-wmv",  # .wmv
            "video/mp4",  # .mp4, .m4v
            "audio/mp4",  # .m4a
            "video/quicktime",  # .mov
            "video/mpeg",  # .mpeg
            "video/ogg",  # .ogv
            "video/webm",  # .webm
            "video/x-matroska",  # .mkv
            "video/x-flv",  # .flv
            "audio/mpeg",  # .mp3
            "audio/x-wav",  # .wav
            "audio/aac",  # .aac
            "audio/flac",  # .flac
            "audio/ogg",  # .ogg
            "application/pdf",  # .pdf
            "application/msword",  # .doc
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",  # .docx
            "application/vnd.ms-powerpoint",  # .pps
            "application/vnd.openxmlformats-officedocument.presentationml.slideshow",  # .ppsx
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",  # .pptx
            "application/vnd.ms-excel",  # .xls
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",  # .xlsx
        ]

    @property
    def binary(self) -> str:
        return "application/octet-stream"

    @classmethod
    def from_xml(cls, fpath: str | Path) -> "Mime":
        tree = ET.parse(fpath)
        root = tree.getroot()
        return Mime(types=[MimeType.from_xml(mime) for mime in root])

    @classmethod
    def from_xmls(cls, fpaths: List[str | Path] | None = None) -> "Mime":
        fpaths = fpaths or cls.default_mime_files()
        trees = [ET.parse(fpath) for fpath in fpaths]
        roots = [tree.getroot() for tree in trees]
        return Mime(types=[MimeType.from_xml(mime) for root in roots for mime in root])

    def __post_init__(self):
        self._type_parents = self._build_type_parents()
        self._extensions = self._build_extensions()
        self._type_exts = self._build_type_exts()
        self._type_mime = self._build_type_mime()
        self._magics = self._build_magics()
        self._bytes_end = max([magic.bytes_end for magic, _ in self._magics], default=0)
        self._patch()

    def exts_of(self, content_type: str) -> List[str] | None:
        return self._type_exts.get(content_type)

    @classmethod
    def _default_patch_file(cls) -> str:
        return os.path.join(os.path.dirname(__file__), "data", "patch.json")

    def _patch(self):
        with open(self._default_patch_file()) as fi:
            patches = json.load(fi)
        for patch in patches:
            type = patch["type"]
            extensions = patch["extensions"] or []
            parents = patch["parents"] or []
            magic = patch["magic"]

            extensions += self._type_exts.get(type, [])
            extensions = _dedup(extensions)
            parents += self._type_parents.get(type, [])
            parents = _dedup(parents)
            self._patch_magic(type, extensions, parents, magic)

    def _patch_magic(
        self,
        type: str,
        extensions: List[str],
        parents: List[str],
        magic: MagicPatch | None,
    ):
        self._type_exts[type] = extensions
        self._type_parents[type] = parents
        for ext in extensions:
            self._extensions[ext] = type
        if magic:
            self._magics.insert(0, (self._build_patched_magic(magic), type))

    def _remove(self, type: str):
        del self._extensions[type]
        self._magics = [m for m in self._magics if m[1] != type]
        del self._type_exts[type]
        del self._type_parents[type]

    def _build_patched_magic(self, magic: MagicPatch) -> Magic:
        return Magic([self._build_patched_match(match_) for match_ in magic])

    def _build_patched_match(self, match_: MatchPatch) -> Match:
        if len(match_) == 2:
            children = []
        else:
            children = [self._build_patched_match(child) for child in match_[2]]
        return Match(
            value=match_[1],
            offset=match_[0],
            type="string",
            children=children,
            mask=None,
        )

    def _build_type_parents(self) -> Dict[str, List[str]]:
        ret: Dict[str, List[str]] = {}
        for t in self.types:
            if t.parents:
                lst = ret[t.type] = ret.get(t.type) or []
                lst.extend(t.parents)
        return ret

    def _build_extensions(self) -> Dict[str, str]:
        ret = {}
        for t in self.types:
            for g in t.globs:
                if GLOB_PAT.match(g.pattern):
                    ret[g.pattern[2:]] = t.type
        return ret

    def _build_type_exts(self) -> Dict[str, List[str]]:
        ret = {}
        for t in self.types:
            for g in t.globs:
                if GLOB_PAT.match(g.pattern):
                    lst = ret[t.type] = ret.get(t.type) or []
                    lst.append(g.pattern[2:])
        return ret

    def _build_type_mime(self) -> Dict[str, MimeType]:
        ret = {}
        for t in self.types:
            ret[t.type] = t
        return ret

    def _build_magics(self) -> List[Tuple[Magic, str]]:
        ret: List[Tuple[Magic, str]] = []
        lp: List[Tuple[Magic, str]] = []
        hp: List[Tuple[int, Tuple[Magic, str]]] = []

        for t in self.types:
            for m in t.magics:
                ret.append((m, t.type))
        ret.sort(key=lambda r: -r[0].priority)
        common_types = {t: idx for idx, t in enumerate(self._common_types)}
        for r in ret:
            if r[1] in common_types:
                hp.append((common_types[r[1]], r))
                del common_types[r[1]]
            else:
                lp.append(r)
        hp.sort(key=lambda r: r[0])
        ret = [r for _, r in hp] + lp
        return ret

    def __call__(
        self,
        pathname_or_io: Path | str | IO[bytes] | None = None,
        name: str | None = None,
        extension: str | None = None,
        declared_type: str | None = None,
    ) -> str | None:

        filename_type = self.for_name(name) or self.for_extension(extension)
        return self._most_specific_type(
            self.for_data(pathname_or_io),
            self.for_declared_type(declared_type),
            filename_type,
            self.binary,
        )

    def _most_specific_type(self, *candidates: str | None) -> str:
        dedup = set()
        lst: List[str] = []
        for candidate in candidates:
            if candidate and candidate not in dedup:
                dedup.add(candidate)
                lst.append(candidate)
        t = lst[0]
        for candidate in lst:
            if self.is_child(candidate, t):
                t = candidate
        return t

    def is_child(self, child: str, parent: str) -> bool:
        parents = self._type_parents.get(child)
        if not parents:
            return False
        if parent in parents:
            return True
        for p in parents:
            if self.is_child(p, parent):
                return True
        return False

    def for_name(self, name: str | None) -> str | None:
        if name and (magic := self._by_path(name)) is not None:
            return magic.lower()
        return None

    def for_extension(self, extension: str | None) -> str | None:
        if extension and (magic := self._by_extension(extension)) is not None:
            return magic.lower()
        return None

    def _by_path(self, name: str) -> str | None:
        return self._by_extension(Path(name).suffix)

    def _by_extension(self, ext: str) -> str | None:
        ext = ext.lower()
        if ext[0] == ".":
            ext = ext[1:]
        return self._extensions.get(ext)

    def for_data(self, pathname_or_io: Path | str | IO[bytes] | None) -> str | None:
        if pathname_or_io:
            with self._with_io(pathname_or_io) as io:
                if (magic := self._by_magic(io)) is not None:
                    return magic.lower()
        return None

    def for_declared_type(self, declared_type: str | None) -> str | None:
        type = self.parse_media_type(declared_type)
        return type if type != self.binary else None

    def _by_magic(self, io: IO[bytes]) -> str | None:
        data = io.read(self._bytes_end)
        for magic, type in self._magics:
            for match_ in magic.matchs:
                if self._match(data, match_):
                    return type
        return None

    def _match(self, data: bytes, match_: Match) -> bool:
        if all(
            self._match_segment(data, segment, match_.offset)
            for segment in match_.segments
        ):
            if len(match_.children) == 0:
                return True
            matched = 0
            for child in match_.children:
                if self._match(data, child):
                    matched += 1
                    if matched >= match_.min_should_match:
                        return True
        return False

    def _match_segment(
        self, data: bytes, segment: Segment, offset: Tuple[int, int] | int
    ) -> bool:
        if isinstance(offset, tuple):
            slice = data[offset[0] : offset[1]]
            return len(slice) > 0 and segment[0] in slice
        if isinstance(segment[1], int):
            return data[segment[1] + offset : segment[2] + offset] == segment[0]
        else:
            return (
                bytes(
                    [
                        b1 & b2
                        for b1, b2 in zip(
                            data[offset : offset + len(segment[0])], segment[1]
                        )
                    ]
                )
                == segment[0]
            )

    def parse_media_type(self, content_type: str | None) -> str | None:
        if content_type:
            result = CONTENT_TYPE_SPLITTER.split(content_type.lower(), 1)[0]
            if result and result.find("/") > 0:
                return result
        return None

    @contextmanager
    def _with_io(
        self, pathname_or_io: Path | str | IO[bytes]
    ) -> Generator[IO[bytes], Any, None]:
        if isinstance(pathname_or_io, Path) or isinstance(pathname_or_io, str):
            with open(pathname_or_io, "rb") as fi:
                yield fi
        else:
            yield pathname_or_io


MIME = Mime.from_xmls()
