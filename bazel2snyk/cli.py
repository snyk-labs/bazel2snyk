import requests
import typer
import math
import time
import sys
import json
import logging
from enum import Enum
from typing import Optional
from snyk import SnykClient
from bazel2snyk import DepGraph
from bazel2snyk import BazelXmlParser
from bazel2snyk.bazel import BazelNodeType
from bazel2snyk.common import logger

#set up logging
# logger = logging.getLogger(__name__)
# FORMAT = "[%(filename)s:%(lineno)4s - %(funcName)s ] %(message)s"
# logging.basicConfig(format=FORMAT)
# logger.setLevel(logging.WARN)

app = typer.Typer(add_completion=False)

# globals
# snyk depgraph test/monitor base URLs
DEPGRAPH_BASE_TEST_URL = "/test/dep-graph?org="
DEPGRAPH_BASE_MONITOR_URL = "/monitor/dep-graph?org="

# version is required by Snyk depGraph API
# setting bazel targets version as "bazel"
BAZEL_TARGET_VERSION_STRING = "bazel"

# set allowable package sources
allowable_package_sources = ["maven", "pip"]
BazelPackageSource = Enum('PackageSource', allowable_package_sources)

visited = []
visited_temp = []

dep_path_counts = {}
target_path_counts = {}

def package_source_callback(value: str):
    """
    Check if specified package-source is a valid value
    """
    typer.echo(f"package_source: {value}")

    if value not in allowable_package_sources:
        raise typer.BadParameter(
            f"Allowable values are {','.join(allowable_package_sources)}, you entered: {value}"
        )
    
    return value

@app.callback(no_args_is_help=True)
def main(ctx: typer.Context,
    bazel_deps_xml: str = typer.Option(
        "bazel_deps.xml",
        envvar=" bazel_deps_xml",
        help="Path to bazel query XML output file"
    ),
    bazel_target: str = typer.Option(
        ...,
        envvar="BAZEL_TARGET",
        help="Name of the target, e.g. //store/api:main"
    ),
    package_source: str = typer.Option(
        "maven",
        callback=package_source_callback,
        case_sensitive=False,
        envvar="PACKAGE_SOURCE",
        help="Name of the target, e.g. //store/api:main"
    ),
    alt_repo_names: str = typer.Option(
        None,
        case_sensitive=False,
        envvar="ALT_REPO_NAMES",
        help="specify comma-delimitied list f you have repos with different names for either @maven or @pypi, e.g. @maven_repo_1, @maven_repo_2"
    ),
    debug: bool = typer.Option(
        False,
        help="Set log level to debug"
    ),
    print_deps: bool = typer.Option(
        False,
        help="Print bazel dependency structure"
    ),
    prune_all: bool = typer.Option(
        False,
        help="Prune all repeated sub-dependencies"
    ),
    prune: bool = typer.Option(
        False,
        help="Prune repeated sub-dependencies that cross a threshold"
    )
):

    if debug:
        typer.echo("*** DEBUG MODE ENABLED ***", file=sys.stderr)
        logger.setLevel(logging.DEBUG)
    elif print_deps:
        logger.setLevel(logging.INFO)

    logger.debug(f"{prune=}")
    logger.debug(f"{prune_all=}")

    global package_source_string
    package_source_string = package_source
    logger.debug(f"{package_source_string=}")

    global bazel_deps_xml_contents
    bazel_deps_xml_contents = load_file(bazel_deps_xml)

    global bazel_xml_parser
    bazel_xml_parser = BazelXmlParser(
        rules_xml=bazel_deps_xml_contents, 
        pkg_manager_name=package_source_string,
        alt_repo_names=alt_repo_names
    )

    global dep_graph
    dep_graph = DepGraph(package_source_string)

    typer.echo(f"Bazel query output file loaded", file=sys.stderr)
    
    typer.echo("----------------------------", file=sys.stderr)

    typer.echo(f"Processing bazel deps XML for target: {bazel_target}, " \
        "this may take a minute ...", file=sys.stderr)
    
    bazel_to_depgraph(parent_node_id=bazel_target, depth=0)
    
    if prune_all:
        logger.info("Pruning graph ...")
        time.sleep(2)
        prune_graph_all()
    elif prune:
        time.sleep(2)
        logger.info("Smart pruning graph (experimental) ...")
        prune_graph(20,5)
    
    return

@app.command()
def print_graph():
    print(f"{json.dumps(dep_graph.graph(), indent=4)}")

@app.command()
def test(
    summarize: bool = typer.Option(
        False, 
        "--summarize", 
        help="Display summarized stats of the snyk test, rather than the complete JSON output"
    ),
    snyk_token: str = typer.Option(
        None,
        envvar="SNYK_TOKEN",
        help="Please specify your Snyk token"
    )
    ,
    snyk_org_id: str = typer.Option(
        None,
        envvar="SNYK_ORG_ID",
        help="Please specify the Snyk ORG ID to run commands against"
    )
):
    snyk_client = SnykClient(snyk_token)
    typer.echo("Snyk client created successfully", file=sys.stderr)

    #dep_graph: DepGraph = g['dep_graph']
    typer.echo("Testing depGraph via Snyk API ...", file=sys.stderr)
    response: requests.Response = snyk_client.post(f"{DEPGRAPH_BASE_TEST_URL}{snyk_org_id}", body=dep_graph.graph())
    
    json_response = response.json()
    print(json.dumps(json_response, indent=4))

    if str(json_response['ok']) == "False":
        typer.echo("exiting with code 1", file=sys.stderr)
        sys.exit(1)

@app.command()
def monitor(
    snyk_token: str = typer.Option(
        None,
        envvar="SNYK_TOKEN",
        help="Please specify your Snyk token"
    )
    ,
    snyk_org_id: str = typer.Option(
        None,
        envvar="SNYK_ORG_ID",
        help="Please specify the Snyk ORG ID to run commands against"
    ),
    snyk_project_name: Optional[str] = typer.Option(
        None,
        envvar="SNYK_PROJECT_NAME",
        help="Specify a custom Snyk project name. By default Snyk will use the name of the root node."
    ),
):
    snyk_client = SnykClient(snyk_token)
    typer.echo("Snyk client created successfully", file=sys.stderr)

    # If an optional project name is passed, then rename the depgraph
    if snyk_project_name:
        typer.echo("Custom project name passed - renaming depgraph", file=sys.stderr)
        dep_graph.rename_depgraph(snyk_project_name)

    typer.echo("Monitoring depGraph via Snyk API ...", file=sys.stderr)
    response: requests.Response = snyk_client.post(f"{DEPGRAPH_BASE_MONITOR_URL}{snyk_org_id}", body=dep_graph.graph())
    
    json_response = response.json()
    print(json.dumps(json_response, indent=4))

    if str(json_response['ok']) == "False":
        typer.echo("exiting with code 1", file=sys.stderr)
        sys.exit(1)


# utility functions
# -----------------
def bazel_to_depgraph(
    parent_node_id: str,
    depth: int
) -> DepGraph:
    """ 
    Recursive function that will walk the bazel dep tree.
    """

    global visited_temp

    # dep_graph: DepGraph = g['dep_graph']

    children = bazel_xml_parser.get_children_from_rule(
        parent_node_id=parent_node_id
    )
    logger.debug(f"{parent_node_id} child count: {len(children)}")

    parent_dep_snyk = snyk_dep_from_bazel_dep(
        parent_node_id,
        bazel_deps_xml_contents,
        package_source_string
    )

    # special entry for the root node of the dep graph
    if depth == 0:
        dep_graph.set_root_node_package(f"{parent_dep_snyk}")
    
    for child in children:
        child_dep_for_snyk = ""
        output_padding = ""

        # set output padding for --print-deps option
        for i in range(0, depth):
            output_padding += "- - "

        if bazel_xml_parser.get_node_type(child) in [
              BazelNodeType.INTERNAL_TARGET,
              BazelNodeType.EXTERNAL_TARGET,
              BazelNodeType.DEPENDENCY
          ]:
              logger.info(f"{output_padding}{child}")
  
        child_dep_for_snyk = snyk_dep_from_bazel_dep(child, bazel_deps_xml_contents, package_source_string)
        logger.debug(f"adding pkg {child_dep_for_snyk=}")
        dep_graph.add_pkg(child_dep_for_snyk)

        # keep track of how many times each dep is encountered 
        if bazel_xml_parser.get_node_type(child) in [
              BazelNodeType.DEPENDENCY
          ]:
              increment_dep_path_count(child_dep_for_snyk)

        elif bazel_xml_parser.get_node_type(child) in [
              BazelNodeType.INTERNAL_TARGET,
              BazelNodeType.EXTERNAL_TARGET
          ]:
              increment_target_path_count(child_dep_for_snyk)

        logger.debug(f"adding dep {child_dep_for_snyk=} for {parent_dep_snyk=}")
        dep_graph.add_dep(child_dep_for_snyk, parent_dep_snyk)
  
        visited_temp.append(parent_node_id)

        # if we've already processed this subtree, then just return
        if child not in visited:
            bazel_to_depgraph(child, depth=depth+1)
       # else:
            # future use for smarter pruning
            # account for node in the subtree to count all paths
    
    # we've reach a leaf node and just need to add an entry with empty deps array
    if len(children) == 0:
        dep_graph.add_dep(child_node_id=None, parent_node_id=parent_dep_snyk)
        visited.extend(visited_temp)

        visited_temp = []

def snyk_dep_from_bazel_dep(bazel_dep_id: str, bazel_query_xml: str, package_source: BazelPackageSource) -> str:
    logger.debug(f"{package_source=}")
    node_type: BazelNodeType = bazel_xml_parser.get_node_type(bazel_dep_id)
    logger.debug(f"{node_type=}")

    if node_type == BazelNodeType.DEPENDENCY:
        snyk_dep = bazel_xml_parser.get_coordinates_from_bazel_dep(bazel_dep_id, package_source)
        logger.debug(f"{snyk_dep=}")
        return snyk_dep
    else:
        return f"{bazel_dep_id}@{BAZEL_TARGET_VERSION_STRING}"

def increment_dep_path_count(dep: str):
    dep_path_counts[dep] = dep_path_counts.get(dep, 0) + 1

def increment_target_path_count(dep: str):
    target_path_counts[dep] = target_path_counts.get(dep, 0) + 1

def prune_graph_all():
    for dep, instances in dep_path_counts.items():
        if instances > 2:
            logger.info(f"pruning {dep} ({instances=})")
            dep_graph.prune_dep(dep)

    for dep, instances in target_path_counts.items():
        if instances > 10:
            logger.info(f"pruning {dep} ({instances=})")
            dep_graph.prune_dep(dep)

def prune_graph(instance_count_threshold: int, instance_percentage_threshold: int):
    dep_path_counts.update(target_path_counts)
    combined_path_counts = dep_path_counts
    
    total_item_count = 0
    
    for dep, instances in combined_path_counts.items():
        total_item_count += instances
    logger.debug(f"{total_item_count=}")
    
    for dep, instances in combined_path_counts.items():
        if instances > 1:
            instance_percentage = math.ceil((instances/total_item_count)*100)
            if instances > instance_count_threshold or instance_percentage > instance_percentage_threshold:
                logger.info(f"pruning {dep} ({instances=}/{instance_count_threshold},{instance_percentage=}/{instance_percentage_threshold})")
                dep_graph.prune_dep(dep)

def load_file(file_path: str) -> str:
    """ return an open file handle"""
    f = open(file_path)
    data = f.read()
    f.close()
    return data

# application entrypoint
# -----------------------
if __name__ == "__main__":
    app()
