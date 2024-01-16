from dataclasses import dataclass
from enum import Enum
from typing import List
import sys
import re
import logging
#import xml.etree.ElementTree as ET
from xml.etree import ElementTree

logger = logging.getLogger(__name__)
FORMAT = "[%(filename)s:%(lineno)4s - %(funcName)s ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)
#logger.setLevel(logging.DEBUG)

# valid types of packages to process
package_sources = {
    "maven": "@maven",
    "pip": "@py_deps"
}

BazelPackageSource = Enum('PackageSource', {value:key for key, value in package_sources.items()})

class BazelNodeType(Enum):
    INTERNAL_TARGET = 1
    EXTERNAL_TARGET = 2
    DEPENDENCY =3
    OTHER = 4

    def __eq__(self, other):
        return self.__class__ is other.__class__ and other.value == self.value

class BazelXmlParser(object):
    def __init__(
        self,
        rules_xml: str,
        pkg_manager_name: str = "maven",
        debug: bool = False,
        bazel_query_output: str = None
    ):
        self.pkg_manager_name = pkg_manager_name
        self.rules_xml = rules_xml
        self.rules = ElementTree.fromstring(rules_xml)
        self.dep_cache = []

    def get_coordinates_from_bazel_dep(self, bazel_dep, package_source):
        dep_coordinates = bazel_dep
        logger.debug(f"{package_sources[package_source]=}")
        bazel_rules = self.rules

        for rule in bazel_rules.findall('rule'):
            #logger.debug(f"processing {rule.attrib['name']=}")
            if (
                    re.match(r".*/BUILD(\.bzl|\.bazel)?\:\d+\:\d+$", rule.attrib['location']) and
                    rule.attrib['name'] == bazel_dep and
                    (
                        rule.attrib['name'].startswith(f"{package_sources[package_source]}//") or
                        re.match(fr"^{package_sources[package_source]}_\w+//", rule.attrib['name'])
                    )
                    
            ):
                # logger.debug(f"found the rule with name: {rule.attrib['name']}")
                # dynamically call the correct conversion function by name
                func = getattr(self, f"_get_coordinates_{package_source}")
                dep_coordinates = func(bazel_dep, rule)
                dep_coordinates = self.get_snyk_dep_from_coordinates(dep_coordinates, package_source)
        return dep_coordinates

    def _get_coordinates_pip(self, bazel_dep, rule):
        # if we dont find a match, return itself
        dep_coordinates = bazel_dep

        bazel_dep_prefix = bazel_dep.split(":")[0]
        logger.debug(f"{bazel_dep_prefix=}")

        children = rule.findall("./list[@name='data']/label")
        # child of data looks like this
        # <label value="@py_deps//pypi__requests:requests-2.23.0.dist-info/LICENSE"/>
        for child in children:
            logger.debug(f"{ElementTree.tostring(child)=}")
            if child.attrib['value'].startswith(bazel_dep_prefix):
                child_value = str(child.attrib['value'])
                dep_coordinates = child_value
                return dep_coordinates

        return dep_coordinates

    def _get_coordinates_maven(self, bazel_dep, rule: ElementTree):
        # if we dont find a match, return itself
        dep_coordinates = bazel_dep

        children = rule.findall("./list[@name='tags']/string")
        # child of data looks like this
        # <string value="maven_coordinates=org.eclipse.jetty.websocket:websocket-servlet:9.4.40.v20210413"/>
        for child in children:
          if child.attrib['value'].startswith("maven_coordinates="):
              logger.debug(f"processing {child.attrib['value']=}")
              child_value = str(child.attrib['value']).split("=").pop()
              dep_coordinates = child_value
              return dep_coordinates
        
        return dep_coordinates
    
    def get_snyk_dep_from_coordinates(self, dep_coordinates: str, package_source):
        logger.debug(f"{package_source=}")
        for data in BazelPackageSource:
            logger.debug(f"checking if {package_source=} matches {data.value=}")
            if package_source == data.value:
                func = getattr(self, f"{data.value}_bazel_dep_to_snyk_dep")
                return func(dep_coordinates)


    def maven_bazel_dep_to_snyk_dep(self, dep_coordinates: str):
        k = dep_coordinates.rfind(":")
        snyk_dep = dep_coordinates[:k] + "@" + dep_coordinates[k+1:]
        return snyk_dep

    def pip_bazel_dep_to_snyk_dep(self, dep_coordinates: str):
        snyk_dep = dep_coordinates
        match = re.search(r"\@.*\/\/pypi__.*\:(.*).dist\-info.*\/", dep_coordinates)
        if match:
            snyk_dep = match.group(1)
            k = snyk_dep.rfind("-")
            snyk_dep = snyk_dep[:k] + "@" + snyk_dep[k+1:]
    
        return snyk_dep
    
    def get_node_type(self, node_id: str) -> BazelNodeType:
        #if (node_id.startswith("@maven//:")):
        if (node_id.startswith(tuple(package_sources.values()))):
            node_type = BazelNodeType.DEPENDENCY
        elif re.match(r"^\/\/.+\:.+$", node_id):
            node_type = BazelNodeType.INTERNAL_TARGET
        elif re.match(r"^(@.+){0,1}\/\/.*\:.*$", node_id):
            node_type = BazelNodeType.EXTERNAL_TARGET
        else:
            node_type = BazelNodeType.OTHER
        return node_type
    
    def get_children_from_rule(self, parent_node_id: str) -> List[str]:
        logger.debug(f"{parent_node_id}")

        filtered_list = [x for x in self.dep_cache if x['parent_node_id'] == parent_node_id]
        if filtered_list:
            # print("cache hit")
            return filtered_list[0]['children']

        bazel_rules = self.rules
        child_deps = []

        node_type = BazelNodeType.OTHER

        for rule in bazel_rules.findall('rule'):
            match = re.match(r".*/BUILD(\.bzl|\.bazel)?\:\d+\:\d+$", rule.attrib['location'])
            if not match:
                continue

            if rule.attrib['name'] == parent_node_id:  
                # print(f"found {parent_node_id=}")
                node_type = self.get_node_type(rule.attrib['name'])

                logger.debug(f"{node_type}")

                # get the maven coordinates for the parent node
                # if node_type == BazelNodeType.DEPENDENCY:
                #     tag = rule.find("./list[@name='tags']/string")
                #     logger.debug(f"{tag=}")
                #     maven_coordinates = str(tag.attrib['value']).split("=").pop()

                if node_type == BazelNodeType.OTHER:
                    continue

                for dep_list in (
                    rule.findall(".//list[@name='deps']") or
                    rule.findall(".//list[@name='runtime_deps']")
                ):
                    for dep in dep_list:
                        child_deps.append(dep.attrib['value'])
        
        self.dep_cache.append(
            {
                "parent_node_id": parent_node_id,
                "children": child_deps
            }
        )

        return child_deps
