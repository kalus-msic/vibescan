from scanner.modules.base import guide_url


class TestGuideUrl:
    def test_prompt_anchor_routes_to_prompts(self):
        assert guide_url("csrf-forms") == "/guide/prompts/#csrf-forms"

    def test_narrative_anchor_routes_to_topics(self):
        assert guide_url("section-idor") == "/guide/topics/#section-idor"

    def test_unknown_anchor_defaults_to_prompts(self):
        # Pojistka — radši na prompts než 404
        assert guide_url("zcela-neznamy-anchor") == "/guide/prompts/#zcela-neznamy-anchor"
