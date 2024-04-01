import pytest
import os
import bazel2snyk
from bazel2snyk.cli import Bazel2Snyk
from bazel2snyk.cli import BazelPackageSource
from bazel2snyk.cli import load_file
from bazel2snyk.bazel import BazelXmlParser
from bazel2snyk.depgraph import DepGraph

BASE_PATH = os.path.dirname(bazel2snyk.__file__)
FIXTURES_PATH = f"{BASE_PATH}/test/fixtures"

PIP_FIXTURES_PATH = f"{FIXTURES_PATH}/pip"
PIP_BAZEL_DEP = "@pypi_click//:pkg"
PIP_SNYK_DEP = "click@8.1.3"
PIP_BAZEL_XML_FILE = f"{PIP_FIXTURES_PATH}/pip.xml"
PIP_PACKAGE_SOURCE: BazelPackageSource = "pip"

MAVEN_FIXTURES_PATH = f"{FIXTURES_PATH}/maven"
MAVEN_BAZEL_DEP = "@maven//:com_google_guava_guava"
MAVEN_SNYK_DEP = "com.google.guava:guava@28.0-jre"
MAVEN_BAZEL_XML_FILE = f"{MAVEN_FIXTURES_PATH}/maven.xml"
MAVEN_PACKAGE_SOURCE: BazelPackageSource = "maven"


@pytest.fixture
def pip_bazel2snyk_instance():
    return Bazel2Snyk(
        BazelXmlParser(
            rules_xml=load_file(PIP_BAZEL_XML_FILE),
            pkg_manager_name=PIP_PACKAGE_SOURCE,
        ),
        DepGraph(PIP_PACKAGE_SOURCE),
    )


def pip_bazel2snyk_alt_instance():
    return Bazel2Snyk(
        BazelXmlParser(
            rules_xml=load_file(PIP_BAZEL_XML_FILE),
            pkg_manager_name=PIP_PACKAGE_SOURCE,
            alt_repo_names="@snyk_py_deps",
        ),
        DepGraph(PIP_PACKAGE_SOURCE),
    )


@pytest.fixture
def maven_bazel2snyk_instance():
    return Bazel2Snyk(
        BazelXmlParser(
            rules_xml=load_file(MAVEN_BAZEL_XML_FILE),
            pkg_manager_name=MAVEN_PACKAGE_SOURCE,
        ),
        DepGraph(MAVEN_PACKAGE_SOURCE),
    )


@pytest.fixture
def maven_bazel2snyk_alt_instance():
    return Bazel2Snyk(
        BazelXmlParser(
            rules_xml=load_file(MAVEN_BAZEL_XML_FILE),
            pkg_manager_name=MAVEN_PACKAGE_SOURCE,
            alt_repo_names="@maven_alt",
        ),
        DepGraph(MAVEN_PACKAGE_SOURCE),
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


def test_pip_alt_snyk_dep_from_bazel_dep(pip_bazel2snyk_instance):
    """
    Test for testing the dep graph
    """
    assert (
        pip_bazel2snyk_instance.snyk_dep_from_bazel_dep(
            PIP_BAZEL_DEP, PIP_PACKAGE_SOURCE
        )
        == PIP_SNYK_DEP
    )


def test_maven_alt_snyk_dep_from_bazel_dep(maven_bazel2snyk_instance):
    """
    Test for testing the dep graph
    """
    assert (
        maven_bazel2snyk_instance.snyk_dep_from_bazel_dep(
            MAVEN_BAZEL_DEP, MAVEN_PACKAGE_SOURCE
        )
        == MAVEN_SNYK_DEP
    )


# TODO: Tests for all functions
# def test_bazel_to_depgraph():
#     """
#     Test for bazel_to_depgraph()
#     """
# def test_prune_graph():
#     """
#     Test for prune_graph()
#     """
#
# def test_prune_graph_all():
#     """
#     Test for prune_graph_all()
#     """
