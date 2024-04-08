import math
from bazel2snyk import logger
from pydantic import BaseModel
from typing import List


class Info(BaseModel):
    name: str
    version: str


class Pkg(BaseModel):
    id: str
    info: Info


class Dep(BaseModel):
    nodeId: str


class Node(BaseModel):
    nodeId: str
    pkgId: str
    deps: List[Dep]


class Graph(BaseModel):
    rootNodeId: str
    nodes: List[Node]


class PkgManager(BaseModel):
    name: str


class DepGraphData(BaseModel):
    schemaVersion: str = "1.2.0"
    pkgManager: PkgManager
    pkgs: List[Pkg]
    graph: Graph


class DepGraphRoot(BaseModel):
    depGraph: DepGraphData


class DepGraph(object):
    def __init__(
        self,
        pkg_manager_name: str,
    ):
        self.pkg_manager_name = pkg_manager_name
        self.meta_pkg_id = "meta-common-packages@meta"
        self.dep_graph = DepGraphRoot(
            depGraph=DepGraphData(
                pkgManager=PkgManager(name=self.pkg_manager_name),
                pkgs=[Pkg(id="app@1.0.0", info=Info(name="app", version="1.0.0"))],
                graph=Graph(
                    rootNodeId="root-node",
                    nodes=[Node(nodeId="root-node", pkgId="app@1.0.0", deps=[])],
                ),
            )
        )
        self._dep_path_counts = {}
        self._target_path_counts = {}

    def graph(self):
        return self.dep_graph

    def set_dep_graph(self, dep_graph):
        # self.dep_graph = dep_graph
        self.dep_graph: DepGraphRoot = dep_graph

    def get_root_node(self):
        graph = self.dep_graph.depGraph.graph
        return graph.rootNodeId

    def _increment_dep_path_count(self, dep: str):
        """
        Increment dep path counts which is later
        used if the dep graph needs to be pruned
        """
        self._dep_path_counts[dep] = self._dep_path_counts.get(dep, 0) + 1

    def _increment_target_path_count(self, dep: str):
        """
        Increment target path counts which is later
        used if the dep graph needs to be pruned
        """
        self._target_path_counts[dep] = self._target_path_counts.get(dep, 0) + 1

    def has_pkg(self, pkg_id: str) -> bool:
        # pkg_id should be in the form of name@version
        # find the right most @ in case there are others
        k = pkg_id.rfind("@")

        # set name and version
        name = pkg_id[:k]
        version = pkg_id[k + 1 :]

        pkg_entry = Pkg(id=f"{name}@{version}", info=Info(name=name, version=version))

        if pkg_entry in self.dep_graph.depGraph.pkgs:
            return True

        return False

    def add_pkg(self, pkg_id: str) -> bool:
        k = pkg_id.rfind("@")

        # set name and version
        name = pkg_id[:k]
        version = pkg_id[k + 1 :]

        pkg_entry = Pkg(id=f"{name}@{version}", info=Info(name=name, version=version))

        if not self.has_pkg(pkg_id):
            self.dep_graph.depGraph.pkgs.append(pkg_entry)
            return True

        return False

    def add_dep(self, child_node_id: str, parent_node_id: str = None):
        logger.debug(f"{parent_node_id=}")
        parent_node = None

        if (
            child_node_id
            and parent_node_id != self.meta_pkg_id
            and child_node_id != self.meta_pkg_id
        ):
            if not child_node_id.startswith("//"):
                self._increment_dep_path_count(child_node_id)
            else:
                self._increment_target_path_count(child_node_id)

        graph_subtree = self.dep_graph.depGraph.graph.nodes

        # first check if element already exists at the specified parent_node_id
        if not parent_node_id:
            logger.debug(
                f"root node, checking for {self.get_root_node()=} in {self.dep_graph.depGraph.graph.nodes}"
            )
            parent_node = [
                x
                for x in self.dep_graph.depGraph.graph.nodes
                if self.get_root_node() == x.nodeId
            ]
        else:
            logger.debug(
                f"not root-node, looking for subtree match for {parent_node_id=} in graph_subtree"
            )
            for subtree_node in graph_subtree:
                logger.debug(f"{subtree_node=}")
                logger.debug(
                    f"checking if parent_node: {parent_node_id} == {subtree_node.nodeId}"
                )
                if parent_node_id == subtree_node.nodeId:
                    parent_node = [subtree_node]
                    break

        logger.debug(f"{parent_node=}")
        logger.debug(f"{child_node_id=}")

        if parent_node:
            if child_node_id:
                dep_entry = Dep(nodeId=child_node_id)

                # append the dep, only if it doesn't already exist as a child
                if dep_entry not in parent_node[0].deps:
                    parent_node[0].deps.append(dep_entry)

        else:  # parent node not found
            logger.debug(f"parent_node not found for {parent_node_id=}")
            if child_node_id:
                graph_entry = Node(
                    nodeId=parent_node_id,
                    pkgId=parent_node_id,
                    deps=[Dep(nodeId=child_node_id)],
                )
                logger.debug(f"setting graph entry with child to {graph_entry}")
            else:
                graph_entry = Node(
                    nodeId=parent_node_id,
                    pkgId=parent_node_id,
                    deps=[],
                )
                logger.debug(f"setting graph entry with no children to {graph_entry}")

            self.dep_graph.depGraph.graph.nodes.append(graph_entry)

    def remove_dep(self, child_node_id: str, parent_node_id: str = None):
        logger.debug(f"removing dep {child_node_id}")
        logger.debug(f"parent_node_id={parent_node_id}")

        # if parent_node_id:
        #    raise Exception("Not implemented")

        graph_subtree = self.dep_graph.depGraph.graph.nodes

        # logger.debug(f"{graph_subtree=}")

        for subtree_node in graph_subtree:
            logger.debug(f"{subtree_node=}")
            logger.debug(
                f"checking if {subtree_node.nodeId} has child dep {child_node_id}"
            )

            child_node_entry = Dep(nodeId=child_node_id)

            logger.debug(f"deps entry to remove: {child_node_entry}")

            if child_node_entry in subtree_node.deps:
                logger.debug(f"removing {child_node_entry} from subtree")
                subtree_node.deps.remove(child_node_entry)

    def set_root_node_package(self, root_node: str):
        logger.debug(f"{root_node=}")

        # root_pkg = self.dep_graph.depGraph.pkgs[0]
        root_pkg = self.dep_graph.depGraph.pkgs[0]
        root_pkg.id = root_node
        root_node_split = root_node.split("@")
        root_pkg.info.name = root_node_split[0]
        root_pkg.info.version = root_node_split[1]

        graph = self.dep_graph.depGraph.graph
        graph.rootNodeId = root_node
        graph.nodes[0].nodeId = root_node
        graph.nodes[0].pkgId = root_node

    def prune_dep(self, node_id: str):
        # create meta-common-packages@meta pkg if does not already exist
        if not self.has_pkg(self.meta_pkg_id):
            self.add_pkg(self.meta_pkg_id)
        # connect meta-common-packages@meta to the root node
        self.add_dep(self.meta_pkg_id)
        # remove instances where this dep is a child from the graph
        self.remove_dep(node_id)
        # add to meta-common-packages@meta
        self.add_dep(node_id, self.meta_pkg_id)

    def prune_graph(
        self, instance_count_threshold: int, instance_percentage_threshold: int
    ):
        """
        Prune graph according to threshold of duplicated transitive dependencies
        """
        self._dep_path_counts.update(self._target_path_counts)
        combined_path_counts = self._dep_path_counts

        total_item_count = 0

        for dep, instances in combined_path_counts.items():
            total_item_count += instances
        logger.debug(f"{total_item_count=}")

        for dep, instances in combined_path_counts.items():
            if instances > 1:
                instance_percentage = math.ceil((instances / total_item_count) * 100)
                if (
                    instances > instance_count_threshold
                    or instance_percentage > instance_percentage_threshold
                ):
                    logger.info(
                        f"pruning {dep} ({instances=}/{instance_count_threshold},{instance_percentage=}/{instance_percentage_threshold})"
                    )
                    self.prune_dep(dep)

    def prune_graph_all(self):
        """
        Prune graph whenever OSS dependencies are repeated more than 2x
        or when bazel target dependencies are repeated more than 10x
        """
        for dep, instances in self._dep_path_counts.items():
            if instances > 2:
                logger.info(f"pruning {dep} ({instances=})")
                self.prune_dep(dep)

        for dep, instances in self._target_path_counts.items():
            if instances > 10:
                logger.info(f"pruning {dep} ({instances=})")
                self.prune_dep(dep)

    def rename_depgraph(self, new_name):
        root_node_id = self.dep_graph.depGraph.graph.rootNodeId
        root_node_index = self._find_node_index(
            self.dep_graph.depGraph.graph, root_node_id
        )
        old_package_name, package_version = self.dep_graph.depGraph.graph.nodes[
            root_node_index
        ].pkgId.split("@")

        # Rename the root note
        self.dep_graph.depGraph.graph.nodes[root_node_index].nodeId = new_name
        self.dep_graph.depGraph.graph.nodes[
            root_node_index
        ].pkgId = f"{new_name}@{package_version}"

        # Rename the packages
        target_package_index = self._find_pkg_index(
            self.dep_graph.depGraph.pkgs, f"{old_package_name}@{package_version}"
        )
        self.dep_graph.depGraph.pkgs[
            target_package_index
        ].id = f"{new_name}@{package_version}"
        self.dep_graph.depGraph.pkgs[target_package_index].info.name = new_name

        # Finally, rename the rootNodeId
        self.dep_graph.depGraph.graph.rootNodeId = new_name

    def _find_node_index(self, graph: Graph, search_node_id):
        # for node in graph.get("nodes", []):
        for node in graph.nodes:
            # if node.get("nodeId") == search_node_id:
            if node.nodeId == search_node_id:
                # return graph.get("nodes", []).index(node)
                return graph.nodes.index(node)
        return -1

    def _find_pkg_index(self, pkgs: List[Pkg], search_id):
        for pkg in pkgs:
            if pkg.id == search_id:
                return pkgs.index(pkg)
        return -1
