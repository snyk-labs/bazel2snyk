![Snyk logo](https://snyk.io/style/asset/logo/snyk-print.svg)

![snyk-oss-category](https://raw.githubusercontent.com/snyk-labs/oss-images/main/oss-community.jpg)

## bazel2snyk

convert the third party dependency output from `bazel query` into a snyk depgraph object to be tested or monitored as a project via the API.

Bazel [targets](https://docs.bazel.build/versions/main/skylark/lib/Target.html) should be mapped to Snyk projects. 

The following command outputs the dependencies in XML format for a given bazel target, that we can further process to be consumed by Snyk.

```
bazel query "deps(//app/package:target)" --noimplicit_deps --output xml > bazel_deps.xml
```

## Usage

The `bazel query` XML output can then be post processed by this script, which provides for the following commands to be used in a CI workflow.

| command     | description                                                                                                                           |
|-------------|---------------------------------------------------------------------------------------------------------------------------------------|
| print-graph | prints converted Snyk depGraph JSON to STDOUT                                                                                         |
| test        | tests the depGraph for issues via Snyk API. Returns exit code 1 if issues are found and prints the tests results JSON to SDOUT        |
| monitor     | submits the depGraph for continuous monitoring via Snyk API. Prints the response JSON to STDOUT including the snapshot URL in snyk.io |

```
Usage: cli.py [OPTIONS] COMMAND [ARGS]...

Options:
  --bazel-deps-xml TEXT           Path to bazel query XML output file  [env
                                  var:  bazel_deps_xml; default:
                                  bazel_deps.xml]
  --bazel-target TEXT             Name of the target, e.g. //store/api:main
                                  [env var: BAZEL_TARGET]
  --package-source [maven|pip]    Name of the target, e.g. //store/api:main
                                  [env var: PACKAGE_SOURCE; default: maven]
  --debug / --no-debug            Set log level to debug  [default: no-debug]
  --print-deps / --no-print-deps  Print bazel dependency structure  [default:
                                  no-print-deps]
  --prune-all / --no-prune-all    Prune all repeated sub-dependencies
                                  [default: no-prune-all]
  --prune / --no-prune            Prune repeated sub-dependencies that cross a
                                  threshold  [default: no-prune]
  --help                          Show this message and exit.

Commands:
  monitor
  print-graph
  test
  ```

export your SNYK_TOKEN before running the script

### print-graph
```
poetry run python3 bazel2snyk/cli.py \
    --bazel-deps-xml=bazel_deps.xml \
    --bazel-target=//app/package:target \
    print-graph
```

### test
```
poetry run python3 bazel2snyk/cli.py \
    --bazel-deps-xml=bazel_deps.xml \
    --bazel-target=//app/package:target \
    test \
    --snyk-org-id=a1f3f68e-99b1-4f3f-bfdb-6ee4b4990513
```

```
Bazel query output file loaded
----------------------------
Processing bazel deps XML for target: //app/package:target, this may take a minute ...
Snyk client created successfully
Testing depGraph via Snyk API ...
{
    "ok": false,
    "packageManager": "maven",
    "issuesData": {
        "SNYK-JAVA-CHQOSLOGBACK-1726923": {
            "CVSSv3": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "credit": [
                "Andrei Komarov"
            ],
            "cvssScore": 4.8,

...

exiting with code 1

```

### monitor
```
poetry run python3 bazel2snyk/cli.py \
    --bazel-deps-xml=bazel_deps.xml \
    --bazel-target=//app/package:target \
    monitor \
    --snyk-org-id=a1f3f68e-99b1-4f3f-bfdb-6ee4b4990513
```

```
Bazel query output file loaded
----------------------------
Processing bazel deps XML for target: //app/package:target, this may take a minute ...
Snyk client created successfully
Monitoring depGraph via Snyk API ...
{
    "ok": true,
    "id": "5dbc3a0f-939a-404c-bd14-bfb0a00e3b3b",
    "uri": "https://app.snyk.io/org/scott.esbrandt-ww9/project/5dbc3a0f-939a-404c-bd14-bfb0a00e3b3b/history/70e0b240-4a39-4795-bb6c-4be16dac6c71"
}
```

### Pruning
If you encounter a HTTP 500 when performing `test` or `monitor` commands, then try to enable pruning.  
What is likely happening is that there are too many vulnerable paths for the system (>100,000), so
pruning the repeated sub-dependencies will alleviate this.

You may run with --prune all the time to avoid this error.

## Supported package types
* maven (tested with rules_jvm_external)
* python pip (tested with rules_python)

## Todo
- Investigate and add support for additional package types
- Automated test suite
- Additional error handling/messages
