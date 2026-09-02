"""Small dependency-free fuzzy scoring primitive used by palette and completion."""

from __future__ import annotations

from difflib import SequenceMatcher


def fuzzy_score(query: str, name: str, searchable: str = "") -> float:
    if not query:
        return 0.0
    if query in name:
        return 3.0 - (name.index(query) / max(len(name), 1))
    compact = "".join(character for character in name if character.isalnum())
    position = 0
    matched = 0
    for character in query:
        found = compact.find(character, position)
        if found < 0:
            break
        matched += 1
        position = found + 1
    subsequence = matched / len(query)
    return max(subsequence * 2.0, SequenceMatcher(None, query, searchable).ratio())