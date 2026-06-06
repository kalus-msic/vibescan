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
