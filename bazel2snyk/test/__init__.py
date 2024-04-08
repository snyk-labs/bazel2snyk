from bazel2snyk import BASE_PATH
from bazel2snyk.cli import BazelPackageSource

FIXTURES_PATH = f"{BASE_PATH}/test/fixtures"

PIP_PACKAGE_SOURCE: BazelPackageSource = "pip"
MAVEN_PACKAGE_SOURCE: BazelPackageSource = "maven"

PIP_FIXTURES_PATH = f"{FIXTURES_PATH}/pip"
PIP_BAZEL_XML_FILE = f"{PIP_FIXTURES_PATH}/pip.xml"
PIP_BAZEL_ALT_XML_FILE = f"{PIP_FIXTURES_PATH}/pip_alt_repo_name.xml"

MAVEN_FIXTURES_PATH = f"{FIXTURES_PATH}/maven"
MAVEN_BAZEL_XML_FILE = f"{MAVEN_FIXTURES_PATH}/maven.xml"
MAVEN_BAZEL_ALT_XML_FILE = f"{MAVEN_FIXTURES_PATH}/maven_alt_repo_name.xml"
MAVEN_BAZEL_MULTIPLE_XML_FILE = f"{MAVEN_FIXTURES_PATH}/maven_multiple_targets.xml"

MAVEN_DEPGRAPH = f"{MAVEN_FIXTURES_PATH}/maven_depgraph.json"
MAVEN_DEPGRAPH_PRUNED = f"{MAVEN_FIXTURES_PATH}/maven_depgraph_pruned.json"
MAVEN_DEPGRAPH_PRUNED_ALL = f"{MAVEN_FIXTURES_PATH}/maven_depgraph_pruned_all.json"
