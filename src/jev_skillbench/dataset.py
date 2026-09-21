"""Load MalSkillBench skills and their labels.

The authoritative label source is `malware/_source_inventory.txt`, which
classifies every entry as GENERATED, WILD, or TEST and, for generated entries,
carries the attack vector and behavior in the source path. Behavior labels for
wild and test entries come from the `*_LABEL` sections of the same file.

When the manifest is absent (for example in a synthetic fixture) the loader
falls back to parsing a `__<VECTOR>_<Bxx>` suffix out of the directory name.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from pathlib import Path

import tiktoken

from .questions import BEHAVIORS

MANIFEST_NAME = "_source_inventory.txt"

# Jev 1.13 accepts 32k tokens for state plus the longest question. Stay under it.
DEFAULT_MAX_TOTAL_TOKENS = 30_000
DEFAULT_MAX_FILE_TOKENS = 12_000

_ENCODER = tiktoken.get_encoding("cl100k_base")

_SUFFIX = re.compile(r"__(?P<vector>CI|PI|MIXED)_(?P<behavior>B\d{1,2})(?:__|$)")
_INVENTORY = re.compile(r"^(GENERATED|WILD|TEST)\s+(?P<entry>.+?)\s*<-\s*(?P<src>.+?)\s*$")
_LABEL = re.compile(r"^(?:WILD|TEST)_LABEL\s+(?P<left>.+?)\s*<-\s*(?P<src>.*)$")

TEXT_SUFFIXES = {
    ".md", ".txt", ".py", ".sh", ".js", ".ts", ".json", ".yaml", ".yml", ".toml",
    ".ini", ".cfg", ".rb", ".go", ".rs",
}

_CODE_SUFFIXES = {".py", ".sh", ".js", ".ts", ".rb", ".go", ".rs", ".bash", ".ps1"}
_DATA_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"}


def _priority(rel: str) -> int:
    lowered = rel.lower()
    if lowered.endswith("skill.md"):
        return 0
    suffix = Path(lowered).suffix
    if suffix in _CODE_SUFFIXES:
        return 1
    if suffix in {".md", ".txt"}:
        return 2
    if suffix in _DATA_SUFFIXES:
        return 3
    return 4


@dataclass
class FilePart:
    path: str
    content: str
    truncated: bool = False


@dataclass
class SkillItem:
    id: str
    label: int
    split: str
    vector: str | None
    behavior: str | None
    behavior_name: str | None
    root: Path
    files: list[FilePart] = field(default_factory=list)
    state_tokens: int = 0
    truncated: bool = False

    def state(self) -> dict:
        return {
            "skill": {
                "name": self.id,
                "files": [{"path": f.path, "content": f.content} for f in self.files],
            }
        }


def parse_name(dirname: str) -> tuple[str, str | None, str | None]:
    m = _SUFFIX.search(dirname)
    if not m:
        return dirname, None, None
    return dirname[: m.start()], m.group("vector").lower(), m.group("behavior")


def _clean_src(src: str) -> str:
    return src.split("#")[0].strip()


def load_manifest(path: str | Path) -> dict[str, dict]:
    path = Path(path)
    if not path.exists():
        return {}
    out: dict[str, dict] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        inv = _INVENTORY.match(line)
        if inv:
            parts = _clean_src(inv.group("src")).split("/")
            vector = parts[1].lower() if parts[0] == "generated_malicious" and len(parts) >= 3 else None
            behavior = parts[2] if vector and len(parts) >= 3 else None
            out[inv.group("entry").strip()] = {
                "split": inv.group(1).lower(),
                "vector": vector,
                "behavior": behavior,
            }
            continue
        lab = _LABEL.match(line)
        if lab:
            columns = re.split(r"\s{2,}", lab.group("left").strip())
            entry = columns[-1]
            behavior = columns[0]
            record = out.setdefault(entry, {"split": None, "vector": None, "behavior": None})
            if record["behavior"] is None:
                record["behavior"] = behavior
    return out


def _read_skill(root: Path, max_file_tokens: int, max_total_tokens: int) -> tuple[list[FilePart], int, bool]:
    candidates = [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in TEXT_SUFFIXES]
    ordered = sorted(candidates, key=lambda p: (_priority(p.relative_to(root).as_posix()), p.relative_to(root).as_posix()))
    parts: list[FilePart] = []
    total = 0
    truncated = False
    for path in ordered:
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:1024]:
            continue
        tokens = _ENCODER.encode(raw.decode("utf-8", errors="replace"), disallowed_special=())
        if len(tokens) > max_file_tokens:
            tokens = tokens[:max_file_tokens]
            truncated = True
        remaining = max_total_tokens - total
        if remaining <= 0:
            truncated = True
            break
        if len(tokens) > remaining:
            tokens = tokens[:remaining]
            truncated = True
        total += len(tokens)
        rel = path.relative_to(root).as_posix()
        parts.append(FilePart(path=rel, content=_ENCODER.decode(tokens)))
    return parts, total, truncated


def load_benchmark(
    skills_root: str | Path,
    max_file_tokens: int = DEFAULT_MAX_FILE_TOKENS,
    max_total_tokens: int = DEFAULT_MAX_TOTAL_TOKENS,
    limit: int | None = None,
    per_class: int | None = None,
    only_generated: bool = False,
    seed: int = 0,
    read_files: bool = True,
) -> list[SkillItem]:
    root = Path(skills_root)
    malware = root / "malware"
    benign = root / "benign"
    if not malware.is_dir() or not benign.is_dir():
        raise FileNotFoundError(f"missing malware/ or benign/ under {root}; run `jev-skillbench fetch` first")

    manifest = load_manifest(malware / MANIFEST_NAME)
    items: list[SkillItem] = []

    for d in sorted(p for p in malware.iterdir() if p.is_dir()):
        meta = manifest.get(d.name)
        if meta:
            split = meta["split"] or "unknown"
            vector = meta["vector"]
            behavior = meta["behavior"]
        else:
            _, vector, behavior = parse_name(d.name)
            split = "generated" if vector else "unknown"
        if only_generated and split != "generated":
            continue
        items.append(
            SkillItem(
                id=d.name,
                label=1,
                split=split,
                vector=vector,
                behavior=behavior,
                behavior_name=BEHAVIORS.get(behavior or "") if behavior else None,
                root=d,
            )
        )

    for d in sorted(p for p in benign.iterdir() if p.is_dir()):
        items.append(
            SkillItem(id=d.name, label=0, split="benign", vector=None, behavior=None, behavior_name=None, root=d)
        )

    if read_files:
        for item in items:
            item.files, item.state_tokens, item.truncated = _read_skill(
                item.root, max_file_tokens=max_file_tokens, max_total_tokens=max_total_tokens
            )

    if per_class is not None:
        rng = random.Random(seed)
        keep: list[SkillItem] = []
        for label in (0, 1):
            pool = [i for i in items if i.label == label]
            rng.shuffle(pool)
            keep.extend(pool[:per_class])
        order = {id(i): n for n, i in enumerate(items)}
        items = sorted(keep, key=lambda i: order[id(i)])
    elif limit is not None:
        items = items[:limit]

    return items
