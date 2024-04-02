from bazel2snyk.test import PIP_FIXTURES_PATH
from bazel2snyk.test import MAVEN_FIXTURES_PATH

pip_fixtures = {
    "pip": f"{PIP_FIXTURES_PATH}/pip.xml",
    "pip_alt_repo_name": f"{PIP_FIXTURES_PATH}/pip_alt_repo_name.xml",
}

maven_fixtures = {
    "maven": f"{MAVEN_FIXTURES_PATH}/maven.xml",
    "maven_alt_repo_name": f"{MAVEN_FIXTURES_PATH}/maven_alt_repo_name.xml",
}

pip_args = {}

pip_args["bad_args"] = [
    # "--debug",
    "--print-deps",
    "--package-source",
    "pip",
    "--bazel-deps-xml",
    f"{pip_fixtures['pip']}",
    "--bazel-target",
    "//snyk/scripts/cli:main",
    "print-graph",
    "--snyk-org-id",
    "abcdefg",
]

pip_args["print_graph"] = [
    # "--debug",
    "--print-deps",
    "--package-source",
    "pip",
    "--bazel-deps-xml",
    f"{pip_fixtures['pip']}",
    "--bazel-target",
    "//snyk/scripts/cli:main",
    "print-graph",
]

pip_args["test"] = [
    # "--debug",
    "--package-source=pip",
    "--bazel-deps-xml",
    f"{pip_fixtures['pip']}",
    "--bazel-target",
    "//snyk/scripts/cli:main",
    "test",
    "--snyk-org-id",
    "fa37c43d-b33f-489a-8708-9b84b6e6211b",
]

pip_args["monitor"] = [
    # "--debug",
    "--package-source",
    "pip",
    "--bazel-deps-xml",
    f"{pip_fixtures['pip']}",
    "--bazel-target",
    "//snyk/scripts/cli:main",
    "monitor",
    "--snyk-org-id",
    "fa37c43d-b33f-489a-8708-9b84b6e6211b",
]

maven_args = {}

maven_args["print_graph"] = [
    # "--debug",
    "--print-deps",
    "--package-source",
    "maven",
    "--bazel-deps-xml",
    f"{maven_fixtures['maven']}",
    "--bazel-target",
    "//:java-maven-lib",
    "print-graph",
]

maven_args["test"] = [
    # "--debug",
    "--package-source=maven",
    "--bazel-deps-xml",
    f"{maven_fixtures['maven']}",
    "--bazel-target",
    "//:java-maven-lib",
    "test",
    "--snyk-org-id",
    "fa37c43d-b33f-489a-8708-9b84b6e6211b",
]

maven_args["monitor"] = [
    # "--debug",
    "--package-source",
    "maven",
    "--bazel-deps-xml",
    f"{maven_fixtures['maven']}",
    "--bazel-target",
    "//:java-maven-lib",
    "monitor",
    "--snyk-org-id",
    "fa37c43d-b33f-489a-8708-9b84b6e6211b",
]
