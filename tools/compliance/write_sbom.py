# Copyright 2023 The Bazel Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""SBOM generator.

This tool takes input from several sources and weaves together an SBOM.

Inputs:
  - the output of packages_used. This is a JSON block of license, package_info
    and other declarations, plus a list of all remote packages referenced.
  - the maven lock file (maven_install.json)
  - the Bazel lock file (MODULE.bazel.lock) when specified
  - FUTURE: other package lock files
  - FUTURE: a user provided override of package URL to corrected information

This tool is private to the sbom() rule.
"""

import argparse
import datetime
import hashlib
import json
import sys
import os


def extract_maven_info_from_url(url: str):
    """Extract groupId, artifactId, and version from a Maven URL."""
    # Remove the base URL
    base_indicators = ["/maven2/", "/repository/"]
    idx = -1
    for indicator in base_indicators:
        idx = url.find(indicator)
        if idx >= 0:
            idx += len(indicator)
            break
    if idx == -1:
        return None, None, None, False

    path = url[idx:]
    segments = path.strip('/').split('/')
    if len(segments) < 4:
        return None, None, None, False

    filename = segments[-1]
    is_sources = filename.endswith('sources.jar')
    # The last segment is the filename, ignore
    # The version is the second segment from the right
    version = segments[-2]
    artifactId = segments[-3].replace('_', '-')
    groupId = '.'.join(segments[:-3])
    return groupId, artifactId, version, is_sources


def parse_release_filename(release_filename: str):
    """Parse release_filename to extract version and name."""
    # Split at the first '/'
    version_and_name = release_filename.split('/', 1)
    if len(version_and_name) != 2:
        return None, None
    version, name_with_ext = version_and_name
    # Remove '.tar.gz' suffix
    if name_with_ext.endswith('.tar.gz'):
        name = name_with_ext[:-len('.tar.gz')]
    else:
        name = name_with_ext
    name = name.replace('_', '-')
    return name, version


def bazel_lock_to_packages(bazel_lock: dict) -> list:
    """Convert MODULE.bazel.lock into a list of dependencies."""
    dependencies = []
    seen_python_packages = set()
    module_extensions = bazel_lock.get("moduleExtensions", {})

    # Process Maven dependencies
    maven_extension = module_extensions.get("@@rules_jvm_external~//:extensions.bzl%maven", {})
    general = maven_extension.get("general", {})
    generated_repo_specs = general.get("generatedRepoSpecs", {})
    for dep_name, dep_info in generated_repo_specs.items():
        attributes = dep_info.get("attributes", {})
        urls = attributes.get("urls", [])
        if not urls:
            continue
        url = urls[0]
        groupId, artifactId, version, is_sources = extract_maven_info_from_url(url)
        if not (groupId and artifactId and version):
            continue
        dependency = {
            "type": "maven",
            "groupId": groupId,
            "artifactId": artifactId,
            "version": version,
            "url": url,
            "is_sources": is_sources,
        }
        dependencies.append(dependency)

    # Process Python dependencies installed with pip
    python_pip_extension = module_extensions.get("@@rules_python~//python/extensions:pip.bzl%pip", {})
    for os_arch_key, os_arch_data in python_pip_extension.items():
        generated_repo_specs = os_arch_data.get("generatedRepoSpecs", {})
        for dep_name, dep_info in generated_repo_specs.items():
            attributes = dep_info.get("attributes", {})
            requirement = attributes.get("requirement")
            if not requirement:
                continue  # Skip dependency if 'requirement' key is missing
            # Parse the requirement to get name and version
            requirement_parts = requirement.strip().split()
            name_version = requirement_parts[0]
            if '==' in name_version:
                name, version = name_version.split('==', 1)
            else:
                continue  # Skip if requirement doesn't have '==' to separate name and version
            package_key = (name.lower(), version)
            if package_key in seen_python_packages:
                continue  # Skip duplicate package
            seen_python_packages.add(package_key)
            # Build the dependency dict
            dependency = {
                "type": "python",
                "name": name,
                "version": version,
            }
            # Construct the URL
            base_url = os.getenv("BAZEL_PYPI_REPOSITORIES")
            dependency["url"] = f"{base_url}/{name}/{version}/{name}-{version}.tar.gz"
            dependencies.append(dependency)

    # Process Python dependencies installed without pip
    python_extension = module_extensions.get("@@rules_python~//python/extensions:python.bzl%python", {})
    general = python_extension.get("general", {})
    generated_repo_specs = general.get("generatedRepoSpecs", {})
    for dep_name, dep_info in generated_repo_specs.items():
        attributes = dep_info.get("attributes", {})
        urls = attributes.get("urls", [])
        if not urls:
            continue  # Skip if 'urls' key is missing or empty
        url = urls[0]
        release_filename = attributes.get("release_filename")
        if not release_filename:
            continue  # Skip if 'release_filename' key is missing
        name, version = parse_release_filename(release_filename)
        if not (name and version):
            continue  # Skip if parsing failed
        package_key = (name.lower(), version)
        if package_key in seen_python_packages:
            continue  # Skip duplicate package
        seen_python_packages.add(package_key)
        dependency = {
            "type": "python_no_pip",
            "name": name,
            "version": version,
            "url": url,
        }
        dependencies.append(dependency)

    return dependencies


def create_sbom_from_dependencies(dependencies: list) -> dict:
    """Creates a dict representing an SBOM from a list of dependencies."""
    now = datetime.datetime.utcnow()
    timestamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    ret = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "documentNamespace": "http://example.com/spdxdocs/example-document",
        "name": "Generated SBOM",
        "creationInfo": {
            "creators": [
                "Tool: write_sbom"
            ],
            "created": timestamp,
        },
        "packages": [],
        "relationships": []
    }

    relationships = ret["relationships"]
    packages = ret["packages"]
    for dep in dependencies:
        if dep["type"] == "maven":
            groupId = dep["groupId"]
            artifactId = dep["artifactId"]
            version = dep["version"]
            url = dep["url"]
            is_sources = dep["is_sources"]
            spdxid = f"SPDXRef-maven-{groupId}-{artifactId}-{version}"
            if is_sources:
                spdxid += "-sources"
            package = {
                "SPDXID": spdxid,
                "downloadLocation": url,
                "filesAnalyzed": False,
                "name": f"{groupId}:{artifactId}",
                "versionInfo": version,
            }
            packages.append(package)
            relationships.append({
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": spdxid,
                "relationshipType": "DESCRIBES"
            })
        elif dep["type"] == "python":
            name = dep["name"]
            version = dep["version"]
            url = dep["url"]
            spdxid = f"SPDXRef-Package-{name}-{version}"
            package = {
                "SPDXID": spdxid,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "name": name,
                "versionInfo": version,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": f"pkg:pypi/{name}@{version}"
                    },
                    {
                        "referenceCategory": "OTHER",
                        "referenceType": "URL",
                        "referenceLocator": url
                    }
                ]
            }
            packages.append(package)
            relationships.append({
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": spdxid,
                "relationshipType": "DESCRIBES"
            })
        elif dep["type"] == "python_no_pip":
            name = dep["name"]
            version = dep["version"]
            url = dep["url"]
            spdxid = f"SPDXRef-Package-{name}-{version}"
            package = {
                "SPDXID": spdxid,
                "downloadLocation": url,
                "filesAnalyzed": False,
                "name": name,
                "versionInfo": version,
            }
            packages.append(package)
            relationships.append({
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": spdxid,
                "relationshipType": "DESCRIBES"
            })
        else:
            # Unknown type, skip
            continue

    ret["packages"] = packages
    ret["relationships"] = relationships
    return ret


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Helper for creating SBOMs", fromfile_prefix_chars="@"
    )
    parser.add_argument(
        "--out", required=True, help="The output file, mandatory."
    )
    parser.add_argument(
        "--packages_used",
        required=False,
        help="JSON list of transitive package data for a target",
    )
    parser.add_argument(
        "--maven_install",
        required=False,
        default="",
        help="Maven lock file",
    )
    parser.add_argument(
        "--bazel_lock",
        required=False,
        default="",
        help="Bazel lock file (MODULE.bazel.lock)",
    )
    opts = parser.parse_args()

    if opts.bazel_lock:
        with open(opts.bazel_lock, "rt", encoding="utf-8") as inp:
            bazel_lock = json.loads(inp.read())
        dependencies = bazel_lock_to_packages(bazel_lock)
        sbom = create_sbom_from_dependencies(dependencies)
    else:
        with open(opts.packages_used, "rt", encoding="utf-8") as inp:
            package_info = json.loads(inp.read())

        maven_packages = None
        if opts.maven_install:
            with open(opts.maven_install, "rt", encoding="utf-8") as inp:
                maven_install = json.loads(inp.read())
                maven_packages = maven_install_to_packages(maven_install)

        sbom = create_sbom(package_info, maven_packages)

    with open(opts.out, "w", encoding="utf-8") as out:
        out.write(json.dumps(sbom, indent=2))


def create_sbom(package_info: dict, maven_packages: dict) -> dict:
    """Creates a dict representing an SBOM.

    Args:
      package_info: dict of data from packages_used output.
      maven_packages: packages gleaned from Maven lock file.

    Returns:
      dict of SBOM data
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    ret = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "documentNamespace": (
            "https://spdx.google/be852459-4c54-4c50-9d2f-0e48890418fc"
        ),
        "name": package_info["top_level_target"],
        "creationInfo": {
            "licenseListVersion": "",
            "creators": [
                "Tool: github.com/bazelbuild/bazel/tools/compliance/write_sbom",
                "Organization: Google LLC",
            ],
            "created": now.isoformat(),
        },
    }

    packages = []
    relationships = []

    relationships.append({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relatedSpdxElement": "SPDXRef-Package-main",
        "relationshipType": "DESCRIBES"
    })

    # This is bazel private shenanigans.
    magic_file_suffix = "//file:file"

    for pkg in package_info["packages"]:
        tmp_id = hashlib.md5()
        tmp_id.update(pkg.encode("utf-8"))
        spdxid = "SPDXRef-GooglePackage-%s" % tmp_id.hexdigest()
        pi = {
            "name": pkg,
            "downloadLocation": "NOASSERTION",
            "SPDXID": spdxid,
        }

        have_maven = None
        if pkg.startswith("@maven//:"):
            have_maven = maven_packages.get(pkg[9:])
        elif pkg.endswith(magic_file_suffix):
            # Bazel hacks jvm_external to add //file:file as a target, then we depend
            # on that rather than the correct thing.
            # Example: @org_apache_tomcat_tomcat_annotations_api_8_0_5//file:file
            # Check for just the versioned root
            have_maven = maven_packages.get(pkg[1:-len(magic_file_suffix)])

        if have_maven:
            pi["downloadLocation"] = have_maven["url"]
        else:
            # TODO: Do something better for this case.
            print("MISSING ", pkg, file=sys.stderr)

        packages.append(pi)
        relationships.append({
            "spdxElementId": "SPDXRef-Package-main",
            "relatedSpdxElement": spdxid,
            "relationshipType": "CONTAINS",
        })

    ret["packages"] = packages
    ret["relationships"] = relationships
    return ret


if __name__ == "__main__":
    main()
