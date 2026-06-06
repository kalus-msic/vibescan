from scanner.lighthouse_audits import AuditMap


def test_audit_map_has_required_fields():
    m = AuditMap(
        finding_id="lh-color-contrast",
        title="Nedostatečný kontrast",
        description="Text",
        category="accessibility",
        fix_url="/guide/pravni-dokumenty/",
    )
    assert m.finding_id == "lh-color-contrast"
    assert m.warn_below == 0.9  # default
    assert m.crit_below == 0.5  # default
    assert m.supersedes_id is None  # default
    assert m.doc_url is None  # default


def test_audit_map_supersedes_can_be_set():
    m = AuditMap(
        finding_id="lh-document-title",
        title="Chybí title",
        description="Text",
        category="seo",
        fix_url="/guide/seo-zaklady/",
        supersedes_id="missing-title",
    )
    assert m.supersedes_id == "missing-title"


from scanner.lighthouse_audits import LIGHTHOUSE_AUDIT_MAP


def test_audit_map_not_empty():
    assert len(LIGHTHOUSE_AUDIT_MAP) >= 20


def test_audit_map_categories_valid():
    valid = {"performance", "accessibility", "best-practices", "seo"}
    for audit_id, mapping in LIGHTHOUSE_AUDIT_MAP.items():
        assert mapping.category in valid, (
            f"{audit_id} has invalid category {mapping.category!r}"
        )


def test_audit_map_finding_ids_prefixed():
    for audit_id, mapping in LIGHTHOUSE_AUDIT_MAP.items():
        assert mapping.finding_id.startswith("lh-"), (
            f"{audit_id}: finding_id must start with 'lh-'"
        )


def test_audit_map_supersedes_ids_known():
    """Every supersedes_id should map to an actual Finding ID produced by
    existing modules. If a module renames a finding, this test catches it."""
    known_finding_ids = {
        # seo.py
        "missing-title", "title-too-long", "title-ok",
        "missing-meta-description", "meta-description-too-long", "meta-description-ok",
        "missing-canonical", "canonical-ok",
        "missing-og-tags", "og-tags-ok",
        "missing-h1", "h1-ok",
        # meta.py
        "meta-generator-version", "meta-generator",
        # accessibility.py
        "skip-link-ok", "missing-skip-link",
        "accessibility-statement-ok", "missing-accessibility-statement",
        "html-lang-ok", "missing-html-lang",
        "missing-img-alt", "img-alt-ok",
        "missing-form-labels",
        "empty-interactive",
        "heading-hierarchy", "heading-hierarchy-ok",
    }
    for audit_id, mapping in LIGHTHOUSE_AUDIT_MAP.items():
        if mapping.supersedes_id is not None:
            assert mapping.supersedes_id in known_finding_ids, (
                f"{audit_id}: supersedes_id {mapping.supersedes_id!r} unknown"
            )
