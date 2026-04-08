import pytest
from dependencies.parsers import parse_requirements_txt, parse_package_json, parse_composer_json, Dependency, parse_dependencies, UnknownFormatError


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


class TestPackageJsonParser:
    def test_dependencies(self):
        content = '{"dependencies": {"express": "^4.18.2", "lodash": "~4.17.21"}}'
        result = parse_package_json(content)
        assert result == [
            Dependency(name="express", version="4.18.2", ecosystem="npm"),
            Dependency(name="lodash", version="4.17.21", ecosystem="npm"),
        ]

    def test_dev_dependencies(self):
        content = '{"devDependencies": {"jest": "29.7.0"}}'
        result = parse_package_json(content)
        assert result == [Dependency(name="jest", version="29.7.0", ecosystem="npm")]

    def test_merges_deps_and_dev_deps(self):
        content = '{"dependencies": {"express": "4.18.2"}, "devDependencies": {"jest": "29.7.0"}}'
        result = parse_package_json(content)
        assert len(result) == 2
        names = {d.name for d in result}
        assert names == {"express", "jest"}

    def test_strips_version_prefixes(self):
        content = '{"dependencies": {"a": "^1.0.0", "b": "~2.0.0", "c": ">=3.0.0", "d": "=4.0.0", "e": "<5.0.0"}}'
        result = parse_package_json(content)
        versions = {d.name: d.version for d in result}
        assert versions == {"a": "1.0.0", "b": "2.0.0", "c": "3.0.0", "d": "4.0.0", "e": "5.0.0"}

    def test_skips_invalid_versions(self):
        content = '{"dependencies": {"express": "4.18.2", "local": "*", "git": "git+https://foo", "latest": "latest"}}'
        result = parse_package_json(content)
        assert result == [Dependency(name="express", version="4.18.2", ecosystem="npm")]

    def test_invalid_json(self):
        assert parse_package_json("not json") == []

    def test_empty_deps(self):
        assert parse_package_json('{"name": "myapp"}') == []


class TestComposerJsonParser:
    def test_require(self):
        content = '{"require": {"laravel/framework": "^10.0", "guzzlehttp/guzzle": "^7.2"}}'
        result = parse_composer_json(content)
        assert result == [
            Dependency(name="laravel/framework", version="10.0", ecosystem="Packagist"),
            Dependency(name="guzzlehttp/guzzle", version="7.2", ecosystem="Packagist"),
        ]

    def test_require_dev(self):
        content = '{"require-dev": {"phpunit/phpunit": "^10.1"}}'
        result = parse_composer_json(content)
        assert result == [Dependency(name="phpunit/phpunit", version="10.1", ecosystem="Packagist")]

    def test_ignores_php_and_extensions(self):
        content = '{"require": {"php": ">=8.1", "ext-mbstring": "*", "laravel/framework": "^10.0"}}'
        result = parse_composer_json(content)
        assert result == [Dependency(name="laravel/framework", version="10.0", ecosystem="Packagist")]

    def test_merges_require_and_require_dev(self):
        content = '{"require": {"laravel/framework": "^10.0"}, "require-dev": {"phpunit/phpunit": "^10.1"}}'
        result = parse_composer_json(content)
        assert len(result) == 2

    def test_invalid_json(self):
        assert parse_composer_json("not json") == []

    def test_empty(self):
        assert parse_composer_json('{"name": "my/app"}') == []


class TestAutoDetection:
    def test_detects_requirements_txt(self):
        content = "django==4.2.0\nrequests>=2.31.0"
        result = parse_dependencies(content)
        assert len(result) > 0
        assert result[0].ecosystem == "PyPI"

    def test_detects_package_json(self):
        content = '{"name": "myapp", "dependencies": {"express": "^4.18.2"}}'
        result = parse_dependencies(content)
        assert len(result) == 1
        assert result[0].ecosystem == "npm"

    def test_detects_composer_json(self):
        content = '{"name": "my/app", "require": {"laravel/framework": "^10.0"}}'
        result = parse_dependencies(content)
        assert len(result) == 1
        assert result[0].ecosystem == "Packagist"

    def test_returns_empty_for_unknown_json(self):
        content = '{"foo": "bar"}'
        result = parse_dependencies(content)
        assert result == []

    def test_raises_for_garbage(self):
        content = "this is not a dependency file at all"
        with pytest.raises(UnknownFormatError):
            parse_dependencies(content)
