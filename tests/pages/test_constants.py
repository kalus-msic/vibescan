from pages.constants import GUIDE_ANCHOR_PAGE
from pages.views import GUIDE_PROMPTS, NARRATIVE_SECTIONS


class TestGuideAnchorPage:
    def test_every_prompt_id_maps_to_prompts(self):
        for prompt in GUIDE_PROMPTS:
            anchor = prompt.get("id")
            if not anchor:
                continue
            assert anchor in GUIDE_ANCHOR_PAGE, f"prompt anchor missing: {anchor}"
            assert GUIDE_ANCHOR_PAGE[anchor] == "prompts", \
                f"prompt anchor {anchor!r} should map to 'prompts', got {GUIDE_ANCHOR_PAGE[anchor]!r}"

    def test_every_narrative_id_maps_to_topics(self):
        for section in NARRATIVE_SECTIONS:
            anchor = section["id"]
            assert anchor in GUIDE_ANCHOR_PAGE, f"narrative anchor missing: {anchor}"
            assert GUIDE_ANCHOR_PAGE[anchor] == "topics", \
                f"narrative anchor {anchor!r} should map to 'topics', got {GUIDE_ANCHOR_PAGE[anchor]!r}"

    def test_no_orphan_anchors(self):
        known = set()
        for p in GUIDE_PROMPTS:
            if p.get("id"):
                known.add(p["id"])
        for s in NARRATIVE_SECTIONS:
            known.add(s["id"])
        orphans = set(GUIDE_ANCHOR_PAGE.keys()) - known
        assert not orphans, f"anchors in map but not in any source: {orphans}"

    def test_values_are_valid_pages(self):
        for anchor, page in GUIDE_ANCHOR_PAGE.items():
            assert page in {"prompts", "topics"}, \
                f"anchor {anchor!r} has invalid page {page!r}"
