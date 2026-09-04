"""The shared symbol name universe.

Every build exports about eleven thousand global symbols, and consecutive
builds export very nearly the same ones: across 244 builds there are 15,082
distinct names, and 5,800 of them appear in every single build. Storing the
name list per build cost 254 KiB each, 54 MiB in total, and that was the
largest single item in the store once layouts were addressed per type.

So the names live once, in one ordered universe, and a build records **which**
of them it has as a bitmap. Fifteen thousand bits is under two kilobytes, so
the per-build cost drops from 254 KiB to about 2.5 KiB -- fifty times less for
exactly the same information.

**The universe is append-only.** That is the load-bearing property, not an
implementation detail. If names were sorted, every new symbol would shift the
positions of the ones after it and invalidate every bitmap already written, so
each collection run would have to rewrite all 244 build entries. 8.4 is
explicit that daily churn in the data repository is what runs into the hosting
limits first -- ahead of raw size. Appending means a bitmap written against a
universe of 15,082 names still reads correctly against one of 15,600: the extra
positions are simply absent from it.

RVAs are stored in universe order, matching the set bits in order, so reading a
build back is a single pass over both.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path


class Universe:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.names: list[str] = []
        self._position: dict[str, int] = {}
        self._dirty = False

        if path.exists():
            document = json.loads(path.read_text(encoding="utf-8"))
            self.names = document["names"]
            self._position = {name: i for i, name in enumerate(self.names)}

    def __len__(self) -> int:
        return len(self.names)

    def position(self, name: str) -> int:
        """Position of `name`, appending it if this is the first sighting."""
        found = self._position.get(name)
        if found is None:
            found = len(self.names)
            self.names.append(name)
            self._position[name] = found
            self._dirty = True
        return found

    def save(self) -> None:
        if not self._dirty and self.path.exists():
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(
                {"schema": 1, "count": len(self.names), "names": self.names},
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
        self._dirty = False


def encode(universe: Universe, rvas: dict[str, int]) -> tuple[str, list[int], int]:
    """Return (base64 bitmap, RVAs in universe order, universe size at write time).

    The recorded size is what makes a stale bitmap safe to read: a consumer
    knows how many positions the writer could see, and that any bit beyond that
    was never theirs to set.
    """
    positions = sorted((universe.position(name), name) for name in rvas)
    if positions:
        width = (positions[-1][0] // 8) + 1
    else:
        width = 0

    bitmap = bytearray(width)
    for index, _ in positions:
        bitmap[index // 8] |= 1 << (index % 8)

    ordered = [rvas[name] for _, name in positions]
    return base64.b64encode(bytes(bitmap)).decode("ascii"), ordered, len(universe)


def decode(universe: Universe, bitmap: str, rvas: list[int]) -> dict[str, int]:
    """Reassemble name -> RVA.

    A set bit past the end of the universe is skipped, but its address is still
    consumed: the RVAs are positional against the *bits*, not against the names
    we happen to be able to resolve. Dropping the name and the address together
    shifts every pair after it by one, so a caller asking for one symbol gets
    the address of another -- correct-looking, entirely wrong, and silent.

    That only happens when a build is read against a universe older than the
    one it was written against, which is exactly what a consumer with a cached
    copy will do.
    """
    raw = base64.b64decode(bitmap)
    found: dict[str, int] = {}
    taken = 0
    for index in range(len(raw) * 8):
        if not raw[index // 8] & (1 << (index % 8)):
            continue
        if taken >= len(rvas):
            break
        if index < len(universe.names):
            found[universe.names[index]] = rvas[taken]
        taken += 1
    return found
