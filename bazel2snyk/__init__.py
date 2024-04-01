import logging
import os
import bazel2snyk

BASE_PATH = os.path.dirname(bazel2snyk.__file__)

logger = logging.getLogger(__name__)
FORMAT = "[%(filename)s:%(lineno)4s - %(funcName)s ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.WARN)
