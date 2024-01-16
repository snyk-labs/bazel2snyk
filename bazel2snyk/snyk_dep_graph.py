from dataclasses import dataclass
from typing import List
import logging

logger = logging.getLogger(__name__)
FORMAT = "[%(filename)s:%(lineno)4s - %(funcName)s ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

#@dataclass
#class BazelNodeToSnykNodeMapping:
#    bazel_node_id: str
#    snyk_node_id: str

class DepGraph(object):
    def __init__(
        self,
        pkg_manager_name: str,
        debug: bool = False,
        bazel_query_output: str = None
    ):
        self.pkg_manager_name = pkg_manager_name
        self.meta_pkg_id = "meta-common-packages@meta"
        self.dep_graph = {
          "depGraph": {
            "schemaVersion": "1.2.0",
            "pkgManager": {
              "name": self.pkg_manager_name
            },
            "pkgs": [
              {
               "id": "app@1.0.0",
               "info": {
                  "name": "app",
                  "version": "1.0.0"
                }
              }
            ],
            "graph": {
              "rootNodeId": "root-node",
              "nodes": [
                {
                  "nodeId": "root-node",
                  "pkgId": "app@1.0.0",
                  "deps": []
                }
              ]
            }
          }
        }
        
    def graph(self):
        return self.dep_graph

    def get_root_node(self):
        graph = self.dep_graph['depGraph']['graph']
        return graph['rootNodeId']

    def has_pkg(self, pkg_id: str) -> bool:
        # pkg_id should be in the form of name@version
        # find the right most @ in case there are others
        k = pkg_id.rfind("@")
        
        # set name and version
        name = pkg_id[:k]
        version = pkg_id[k+1:]

        pkg_entry = {
            "id": f"{name}@{version}",
            "info": {
                "name": name,
                "version": version
            }
        }

        if pkg_entry in self.dep_graph['depGraph']['pkgs']:
            return True

        return False 
    
    def add_pkg(self, pkg_id: str) -> bool:
        k = pkg_id.rfind("@")
        
        # set name and version
        name = pkg_id[:k]
        version = pkg_id[k+1:]

        pkg_entry = {
            "id": f"{name}@{version}",
            "info": {
                "name": name,
                "version": version
            }
        }
        
        if not self.has_pkg(pkg_id):
            self.dep_graph['depGraph']['pkgs'].append(pkg_entry)
            return True
        
        return False

    def add_dep(self, child_node_id: str, parent_node_id: str = None):
        logger.debug(f"{parent_node_id=}")
        parent_node = None

        graph_subtree = self.dep_graph['depGraph']['graph']['nodes']

        # first check if element already exists at the specified parent_node_id
        if not parent_node_id:
            logger.debug(f"root node, checking for {self.get_root_node()=} in {self.dep_graph['depGraph']['graph']['nodes']}")
            parent_node = [x for x in self.dep_graph['depGraph']['graph']['nodes'] if self.get_root_node() == x['nodeId']]
        else:
            #logger.debug(f"not root-node, looking for subtree match for {parent_node_id=} in {self.dep_graph['depGraph']['graph']['nodes']=}")
            logger.debug(f"not root-node, looking for subtree match for {parent_node_id=} in {graph_subtree=}")
            #for subtree_node in self.dep_graph['depGraph']['graph']['nodes'][0]['deps']:
            for subtree_node in graph_subtree:
                logger.debug(f"{subtree_node=}")
                logger.debug(f"checking if parent_node: {parent_node_id} == {subtree_node['nodeId']}")
                if parent_node_id == subtree_node['nodeId']:
                    parent_node = [subtree_node]
                    break

        logger.debug(f"{parent_node=}")
        logger.debug(f"{child_node_id=}")

        if parent_node:
            if child_node_id:
                # append the dep,only if it doesn't already exist as a child
                dep_entry = {
                        "nodeId": child_node_id
                    }
                if "deps" not in parent_node[0]:
                    parent_node[0]['deps'] = [dep_entry]

                elif dep_entry not in parent_node[0]['deps']:
                    parent_node[0]['deps'].append(
                        dep_entry
                    )

        else: #parent node not found, so add a new entry with empty deps
          logger.debug(f"parent_node not found for {parent_node_id=}")
          if child_node_id:
            graph_entry = {
                "nodeId": parent_node_id,
                "pkgId": parent_node_id,
                "deps": [{"nodeId": child_node_id}]
            }
            logger.debug(f"setting graph entry with child to {graph_entry}")
          else:
            graph_entry = {
                "nodeId": parent_node_id,
                "pkgId": parent_node_id,
                "deps": []
            }
            logger.debug(f"setting graph entry with no children to {graph_entry}")
            
          self.dep_graph['depGraph']['graph']['nodes'].append(graph_entry)

    def remove_dep(self, child_node_id: str, parent_node_id: str = None):
        logger.debug(f"removing dep {child_node_id}")
        logger.debug(f"parent_node_id={parent_node_id}")

        #if parent_node_id: 
        #    raise Exception("Not implemented")

        graph_subtree = self.dep_graph['depGraph']['graph']['nodes']

        #print(f"{graph_subtree=}")

        for subtree_node in graph_subtree:
                logger.debug(f"{subtree_node=}")
                logger.debug(f"checking if {subtree_node['nodeId']} has child dep {child_node_id}")
                
                child_node_entry = {
                    'nodeId': f'{child_node_id}'
                }

                logger.debug(f"deps entry to remove: {child_node_entry}")

                if child_node_entry in subtree_node['deps']:
                    logger.debug(f"removing {child_node_entry} from subtree")
                    subtree_node['deps'].remove(child_node_entry)

    
    def set_root_node_package(self, root_node: str):
        logger.debug(f"{root_node=}")
        root_pkg = self.dep_graph['depGraph']['pkgs'][0]
        root_pkg['id'] = f"{root_node}"
        root_node_split = root_node.split("@")
        root_pkg['info']['name'] = f"{root_node_split[0]}"
        root_pkg['info']['version'] = f"{root_node_split[1]}"

        graph = self.dep_graph['depGraph']['graph']
        graph['rootNodeId'] = root_node
        graph['nodes'][0]['nodeId'] = root_node
        graph['nodes'][0]['pkgId'] = root_node
    
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

    def rename_depgraph(self, new_name):
        root_node_id = self.dep_graph["depGraph"]["graph"]["rootNodeId"]
        root_node_index = self._find_node_index(self.dep_graph["depGraph"]["graph"], root_node_id)
        old_package_name, package_version = self.dep_graph["depGraph"]["graph"]["nodes"][root_node_index]["pkgId"].split("@")

        # Rename the root note
        self.dep_graph["depGraph"]["graph"]["nodes"][root_node_index]["nodeId"] = new_name
        self.dep_graph["depGraph"]["graph"]["nodes"][root_node_index]["pkgId"] = f"{new_name}@{package_version}"

        # Rename the packages
        target_package_index = self._find_pkg_index(self.dep_graph["depGraph"]["pkgs"], f"{old_package_name}@{package_version}")
        self.dep_graph["depGraph"]["pkgs"][target_package_index]["id"] = f"{new_name}@{package_version}"
        self.dep_graph["depGraph"]["pkgs"][target_package_index]["info"]["name"] = new_name

        # Finally, rename the rootNodeId
        self.dep_graph["depGraph"]["graph"]["rootNodeId"] = new_name

    def _find_node_index(self, graph, search_node_id):
        for node in graph.get("nodes", []):
            if node.get("nodeId") == search_node_id:
                return graph.get("nodes", []).index(node)
        return -1

    def _find_pkg_index(self, pkgs, search_id):
        for pkg in pkgs:
            if pkg["id"] == search_id:
                return pkgs.index(pkg)
        return -1

