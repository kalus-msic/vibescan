import pytest
from dependencies.parsers import parse_requirements_txt, Dependency


class TestRequirementsTxtParser:
    def test_pinned_version(self):
        result = parse_requirements_txt("django==4.2.0\nrequests==2.31.0")
        assert result == [
            Dependency(name="django", version="4.2.0", ecosystem="PyPI"),
            Dependency(name="requests", version="2.31.0", ecosystem="PyPI"),
        ]

    def test_comparison_operators(self):
        result = parse_requirements_txt("django>=4.2.0\nflask<=2.0\ncelery~=5.3.0\nnumpy!=1.24.0,>=1.23.0")
        assert len(result) == 4
        assert result[0] == Dependency(name="django", version="4.2.0", ecosystem="PyPI")
        assert result[1] == Dependency(name="flask", version="2.0", ecosystem="PyPI")
        assert result[2] == Dependency(name="celery", version="5.3.0", ecosystem="PyPI")
        assert result[3] == Dependency(name="numpy", version="1.23.0", ecosystem="PyPI")

    def test_ignores_comments_and_blanks(self):
        content = "# this is a comment\n\ndjango==4.2.0\n  # another comment\n"
        result = parse_requirements_txt(content)
        assert result == [Dependency(name="django", version="4.2.0", ecosystem="PyPI")]

    def test_ignores_flags_and_editables(self):
        content = "-r base.txt\n--index-url https://pypi.org\n-e git+https://github.com/foo/bar.git\ndjango==4.2.0"
        result = parse_requirements_txt(content)
        assert result == [Dependency(name="django", version="4.2.0", ecosystem="PyPI")]

    def test_no_version_skipped(self):
        result = parse_requirements_txt("django\nrequests==2.31.0")
        assert result == [Dependency(name="requests", version="2.31.0", ecosystem="PyPI")]

    def test_extras_ignored(self):
        result = parse_requirements_txt("celery[redis]==5.3.6")
        assert result == [Dependency(name="celery", version="5.3.6", ecosystem="PyPI")]

    def test_empty_input(self):
        assert parse_requirements_txt("") == []
        assert parse_requirements_txt("   \n\n  ") == []
