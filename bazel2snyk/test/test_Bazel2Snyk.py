import pytest
from bazel2snyk.cli import Bazel2Snyk
from bazel2snyk.cli import load_file
from bazel2snyk.bazel import BazelXmlParser
from bazel2snyk.depgraph import DepGraph
from bazel2snyk.test import PIP_PACKAGE_SOURCE
from bazel2snyk.test import PIP_BAZEL_XML_FILE
from bazel2snyk.test import PIP_BAZEL_ALT_XML_FILE
from bazel2snyk.test import MAVEN_PACKAGE_SOURCE
from bazel2snyk.test import MAVEN_BAZEL_XML_FILE
from bazel2snyk.test import MAVEN_BAZEL_ALT_XML_FILE

PIP_BAZEL_DEP = "@pypi_click//:pkg"
PIP_BAZEL_ALT_DEP = "@snyk_py_deps_click//:pkg"
PIP_SNYK_DEP = "click@8.1.3"

MAVEN_BAZEL_DEP = "@maven//:com_google_guava_guava"
MAVEN_BAZEL_ALT_DEP = "@maven_alt//:com_google_guava_guava"
MAVEN_SNYK_DEP = "com.google.guava:guava@28.0-jre"


@pytest.fixture
def pip_bazel2snyk_instance():
    return Bazel2Snyk(
        bazel_xml_parser=BazelXmlParser(
            rules_xml=load_file(PIP_BAZEL_XML_FILE),
            pkg_manager_name=PIP_PACKAGE_SOURCE,
        ),
        dep_graph=DepGraph(PIP_PACKAGE_SOURCE),
    )


@pytest.fixture
def pip_bazel2snyk_alt_instance():
    return Bazel2Snyk(
        bazel_xml_parser=BazelXmlParser(
            rules_xml=load_file(PIP_BAZEL_ALT_XML_FILE),
            pkg_manager_name=PIP_PACKAGE_SOURCE,
            alt_repo_names="@snyk_py_deps",
        ),
        dep_graph=DepGraph(PIP_PACKAGE_SOURCE),
    )


@pytest.fixture
def maven_bazel2snyk_instance():
    return Bazel2Snyk(
        bazel_xml_parser=BazelXmlParser(
            rules_xml=load_file(MAVEN_BAZEL_XML_FILE),
            pkg_manager_name=MAVEN_PACKAGE_SOURCE,
        ),
        dep_graph=DepGraph(MAVEN_PACKAGE_SOURCE),
    )


@pytest.fixture
def maven_bazel2snyk_alt_instance():
    return Bazel2Snyk(
        bazel_xml_parser=BazelXmlParser(
            rules_xml=load_file(MAVEN_BAZEL_ALT_XML_FILE),
            pkg_manager_name=MAVEN_PACKAGE_SOURCE,
            alt_repo_names="@maven_alt",
        ),
        dep_graph=DepGraph(MAVEN_PACKAGE_SOURCE),
    )


def test_pip_snyk_dep_from_bazel_dep(pip_bazel2snyk_instance):
    """
    Test for testing the dep graph
    """
    assert (
        pip_bazel2snyk_instance.snyk_dep_from_bazel_dep(
            PIP_BAZEL_DEP, PIP_PACKAGE_SOURCE
        )
        == PIP_SNYK_DEP
    )


def test_maven_snyk_dep_from_bazel_dep(maven_bazel2snyk_instance):
    """
    Test for testing the dep graph
    """
    assert (
        maven_bazel2snyk_instance.snyk_dep_from_bazel_dep(
            MAVEN_BAZEL_DEP, MAVEN_PACKAGE_SOURCE
        )
        == MAVEN_SNYK_DEP
    )


def test_pip_alt_snyk_dep_from_bazel_dep(pip_bazel2snyk_alt_instance):
    """
    Test for testing the dep graph
    """
    assert (
        pip_bazel2snyk_alt_instance.snyk_dep_from_bazel_dep(
            PIP_BAZEL_ALT_DEP, PIP_PACKAGE_SOURCE
        )
        == PIP_SNYK_DEP
    )


def test_maven_alt_snyk_dep_from_bazel_dep(maven_bazel2snyk_alt_instance):
    """
    Test for testing the dep graph
    """
    assert (
        maven_bazel2snyk_alt_instance.snyk_dep_from_bazel_dep(
            MAVEN_BAZEL_ALT_DEP, MAVEN_PACKAGE_SOURCE
        )
        == MAVEN_SNYK_DEP
    )


# TODO: Tests for all functions
# def test_bazel_to_depgraph():
#     """
#     Test for bazel_to_depgraph()
#     """
