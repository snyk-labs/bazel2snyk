import requests
import typer
import math
import time
import re
import sys
import json
import logging
from enum import Enum
from uuid import UUID
from typing import Optional
from snyk import SnykClient
from bazel2snyk import (
    DepGraph,
    BazelXmlParser
)
from bazel2snyk.bazel import (
    BazelNodeType,
    package_sources
)

#set up logging
logger = logging.getLogger(__name__)
FORMAT = "[%(filename)s:%(lineno)4s - %(funcName)s ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.WARN)

app = typer.Typer(add_completion=False)

# for use of the allowable package sources as choices for CLI
BazelPackageSource = Enum('PackageSource', {value:key for key, value in package_sources.items()})

# globals
g={}

# snyk depgraph test/monitor base URLs
g['DEPGRAPH_BASE_TEST_URL'] = "/test/dep-graph?org="
g['DEPGRAPH_BASE_MONITOR_URL'] = "/monitor/dep-graph?org="

# version is required by Snyk depGraph API
# setting bazel targets version as "bazel"
g['BAZEL_TARGET_VERSION_STRING'] = "bazel"

# set default package source
g['package_source'] = "maven"

# g['dep_graph']: DepGraph = DepGraph("maven", False)

g['processed_subtree_nodes'] = []
g['processed_nodes_temp'] = []

# future use
# g['transitive_closures'] = [] 

g['dep_path_counts'] = {}
g['target_path_counts'] = {}

@app.callback(no_args_is_help=True)
def main(ctx: typer.Context,
    bazel_deps_xml: str = typer.Option(
        "bazel_deps.xml",
        envvar=" bazel_deps_xml",
        help="Path to bazel query XML output file"
    ),
    bazel_target: str = typer.Option(
        None,
        envvar="BAZEL_TARGET",
        help="Name of the target, e.g. //store/api:main"
    ),
    package_source: BazelPackageSource = typer.Option(
        "maven",
        case_sensitive=False,
        envvar="PACKAGE_SOURCE",
        help="Name of the target, e.g. //store/api:main"
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

    g['package_source'] = package_source.value

    g['bazel_deps_xml'] = load_file(bazel_deps_xml)

    g['dep_graph']: DepGraph = DepGraph(g['package_source'], False)

    g['bazel_xml_parser'] = BazelXmlParser(rules_xml=g['bazel_deps_xml'])
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
    bazel_graph = g['bazel_deps_xml']
    dep_graph: DepGraph = g['dep_graph']
    #print(f"{dep_graph.graph()}")
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

    dep_graph: DepGraph = g['dep_graph']
    typer.echo("Testing depGraph via Snyk API ...", file=sys.stderr)
    response: requests.Response = snyk_client.post(f"{g['DEPGRAPH_BASE_TEST_URL']}{snyk_org_id}", body=dep_graph.graph())
    
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

    dep_graph: DepGraph = g['dep_graph']

    # If an optional project name is passed, then rename the depgraph
    if snyk_project_name:
        typer.echo("Custom project name passed - renaming depgraph", file=sys.stderr)
        dep_graph.rename_depgraph(snyk_project_name)

    typer.echo("Monitoring depGraph via Snyk API ...", file=sys.stderr)
    response: requests.Response = snyk_client.post(f"{g['DEPGRAPH_BASE_MONITOR_URL']}{snyk_org_id}", body=dep_graph.graph())
    
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
    dep_graph: DepGraph = g['dep_graph']

    children = g['bazel_xml_parser'].get_children_from_rule(
        parent_node_id=parent_node_id
    )
    logger.debug(f"{parent_node_id} child count: {len(children)}")

    parent_dep_snyk = snyk_dep_from_bazel_dep(
        parent_node_id,
        g['bazel_deps_xml'],
        g['package_source']
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

        if g['bazel_xml_parser'].get_node_type(child) in [
              BazelNodeType.INTERNAL_TARGET,
              BazelNodeType.EXTERNAL_TARGET,
              BazelNodeType.DEPENDENCY
          ]:
              logger.info(f"{output_padding}{child}")
  
        child_dep_for_snyk = snyk_dep_from_bazel_dep(child, g['bazel_deps_xml'], g['package_source'])
        logger.debug(f"adding pkg {child_dep_for_snyk=}")
        dep_graph.add_pkg(child_dep_for_snyk)

        # keep track of how many times each dep is encountered 
        if g['bazel_xml_parser'].get_node_type(child) in [
              BazelNodeType.DEPENDENCY
          ]:
              increment_dep_path_count(child_dep_for_snyk)

        elif g['bazel_xml_parser'].get_node_type(child) in [
              BazelNodeType.INTERNAL_TARGET,
              BazelNodeType.EXTERNAL_TARGET
          ]:
              increment_target_path_count(child_dep_for_snyk)

        logger.debug(f"adding dep {child_dep_for_snyk=} for {parent_dep_snyk=}")
        dep_graph.add_dep(child_dep_for_snyk, parent_dep_snyk)
  
        g['processed_nodes_temp'].append(parent_node_id)

        # if we've already processed this subtree, then just return
        if child not in g['processed_subtree_nodes']:
            bazel_to_depgraph(child, depth=depth+1)
       # else:
            # future use for smarter pruning
            # account for node in the subtree to count all paths
    
    # we've reach a leaf node and just need to add an entry with empty deps array
    if len(children) == 0:
        dep_graph.add_dep(child_node_id=None, parent_node_id=parent_dep_snyk)
        g['processed_subtree_nodes'].extend(g['processed_nodes_temp'])
        g['processed_nodes_temp'] = []

def snyk_dep_from_bazel_dep(bazel_dep_id: str, bazel_query_xml: str, package_source: BazelPackageSource) -> str:
    logger.debug(f"{package_source=}")
    node_type: BazelNodeType = g['bazel_xml_parser'].get_node_type(bazel_dep_id)
    logger.debug(f"{node_type=}")

    if node_type == BazelNodeType.DEPENDENCY:
        snyk_dep = g['bazel_xml_parser'].get_coordinates_from_bazel_dep(bazel_dep_id, package_source)
        logger.debug(f"{snyk_dep=}")
        #snyk_dep = get_snyk_dep_from_coordinates(dep_coordinates, package_source)
        return snyk_dep
    else:
        return f"{bazel_dep_id}@{g['BAZEL_TARGET_VERSION_STRING']}"

def increment_dep_path_count(dep: str):
    g['dep_path_counts'][dep] = g['dep_path_counts'].get(dep, 0) + 1

def increment_target_path_count(dep: str):
    g['target_path_counts'][dep] = g['target_path_counts'].get(dep, 0) + 1

def prune_graph_all():
    dep_graph: DepGraph = g['dep_graph']
    for dep, instances in g['dep_path_counts'].items():
        if instances > 2:
            logger.info(f"pruning {dep} ({instances=})")
            dep_graph.prune_dep(dep)

    for dep, instances in g['target_path_counts'].items():
        if instances > 10:
            logger.info(f"pruning {dep} ({instances=})")
            dep_graph.prune_dep(dep)

def prune_graph(instance_count_threshold: int, instance_percentage_threshold: int):
    dep_graph: DepGraph = g['dep_graph']
    g['dep_path_counts'].update(g['target_path_counts'])
    combined_path_counts = g['dep_path_counts']
    
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
