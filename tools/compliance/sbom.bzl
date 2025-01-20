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
"""Generate an SBOM for a target."""

load(":gather_packages.bzl", "packages_used")

def _sbom_impl(ctx):
    # Gather all licenses and write information to one place

    # Now turn the big blob of data into something consumable.
    outputs = [ctx.outputs.out]
    args = ctx.actions.args()
    inputs = []
    bazel_pypi_repositories = ctx.var.get("BAZEL_PYPI_REPOSITORIES", "https://no-address")
    if ctx.attr.bazel_lock:
        args.add("--bazel_lock", ctx.file.bazel_lock.path)
        inputs.append(ctx.file.bazel_lock)
    else:
        if not ctx.attr.packages_used:
            fail("Either 'packages_used' or 'bazel_lock' must be specified")
        args.add("--packages_used", ctx.file.packages_used.path)
        inputs.append(ctx.file.packages_used)
    args.add("--out", ctx.outputs.out.path)
    if ctx.attr.maven_install:
        args.add("--maven_install", ctx.file.maven_install.path)
        inputs.append(ctx.file.maven_install)
    ctx.actions.run(
        mnemonic = "CreateSBOM",
        progress_message = "Creating SBOM for %s" % ctx.label,
        inputs = inputs,
        outputs = outputs,
        executable = ctx.executable._sbom_generator,
        arguments = [args],
        env = {
            "BAZEL_PYPI_REPOSITORIES": bazel_pypi_repositories,
        },
    )
    return [DefaultInfo(files = depset(outputs))]

_sbom = rule(
    implementation = _sbom_impl,
    attrs = {
        "packages_used": attr.label(
            allow_single_file = True,
            mandatory = False,
        ),
        "bazel_lock": attr.label(
            mandatory = False,
            allow_single_file = True,
        ),
        "out": attr.output(mandatory = True),
        "_sbom_generator": attr.label(
            default = Label("//tools/compliance:write_sbom_private"),
            executable = True,
            allow_files = True,
            cfg = "exec",
        ),
        "maven_install": attr.label(
            mandatory = False,
            allow_single_file = True,
        ),
    },
)

def sbom(
        name,
        target = None,
        out = None,
        maven_install = None,
        bazel_lock = None):
    """Wrapper for sbom rule.

    Args:
        name: name
        target: Target to create sbom for (not used when bazel_lock is specified)
        out: output file name
        maven_install: maven lock file
        bazel_lock: Bazel lock file (MODULE.bazel.lock)
    """
    if bazel_lock:
        if not out:
            out = name + "_sbom.json"
        _sbom(
            name = name,
            out = out,
            bazel_lock = bazel_lock,
            maven_install = maven_install,
        )
    else:
        if not target:
            fail("You must specify a target when not using bazel_lock")
        packages = "_packages_" + name
        packages_used(
            name = packages,
            target = target,
            out = packages + ".json",
        )
        if not out:
            out = name + "_sbom.json"
        _sbom(
            name = name,
            out = out,
            packages_used = ":" + packages + ".json",
            maven_install = maven_install,
        )
