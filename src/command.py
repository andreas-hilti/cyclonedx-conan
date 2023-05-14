#!/usr/bin/env python3
# encoding: utf-8

# This file is part of CycloneDX Conan
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

import argparse
import json
import os.path
import sys
from uuid import uuid4
from conan.api.conan_api import ConanAPI
from conan.cli.command import ConanCommand, OnceArgument
from conan.cli.args import add_common_install_arguments, common_graph_args
from conan.cli.commands.graph import graph_info
from conans.model.recipe_ref import RecipeReference
from conans.client.graph.graph import DepsGraph, Node
from conans.errors import ConanMigrationError, ConanException
from packageurl import PackageURL


class CycloneDXCommand:
    # Parsed Arguments
    _arguments: argparse.Namespace

    def __init__(self, args: argparse.Namespace):
        self._arguments = args

    @staticmethod
    def get_arg_parser() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(description='CycloneDX SBOM Generator')

        parser.add_argument("-if", "--install-folder", action=OnceArgument,
                            help="local folder containing the conaninfo.txt and conanbuildinfo.txt "
                            "files (from a previous conan install execution). Defaulted to "
                            "current folder, unless --profile, -s or -o is specified. If you "
                            "specify both install-folder and any setting/option "
                            "it will raise an error.")
        def remove_argument(parser, argument):
            for action in parser._actions:
                option_strings = action.option_strings
                if (option_strings and option_strings[0] == argument) or action.dest == argument:
                    parser._remove_action(action)
                    break
            for group in parser._action_groups:
                for group_action in group._group_actions:
                    option_strings = group_action.option_strings
                    if (option_strings and option_strings[0] == argument) or group_action.dest == argument:
                        group._group_actions.remove(group_action)
                        break
        common_graph_args(parser)
        remove_argument(parser, "requires")
        remove_argument(parser, "--tool-requires")

        return parser

    def execute(self):
        try:
            conan_api = ConanAPI()
        except ConanMigrationError:  # Error migrating
            sys.exit(1)
        except ConanException as e:
            sys.stderr.write("Error in Conan initialization: {}".format(e))
            sys.exit(1)
        cwd = os.getcwd()
        args = self._arguments

        if not args.path:
            sys.stderr.write("Error: You need to provide the path.")
            sys.exit(1)

        path = conan_api.local.get_conanfile_path(args.path, cwd, py=None)

        remotes = conan_api.remotes.list(args.remote) if not args.no_remote else []
        lockfile = conan_api.lockfile.get_lockfile(lockfile=args.lockfile,
                                                conanfile_path=path,
                                                cwd=cwd,
                                                partial=args.lockfile_partial)
        profile_host, profile_build = conan_api.profiles.get_profiles_from_args(args)


        deps_graph: DepsGraph = conan_api.graph.load_graph_consumer(path, args.name, args.version,
                                                            args.user, args.channel,
                                                            profile_host, profile_build, lockfile,
                                                            remotes, args.build, args.update)

        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.3",
            "serialNumber": "urn:uuid:" + str(uuid4()),
            "version": 1,
            'metadata': {
                'component': {
                    'bom-ref': 'unknown@0.0.0',
                    'type': 'application',
                    'name': 'unknown',
                    'version': '0.0.0',
                },
            },
            'components': [],
            'dependencies': [],
        }
        node:Node
        for node in deps_graph.nodes:
            if not node.inverse_neighbors():
                # top level component
                bom['metadata']['component']['name'] = os.path.basename(os.path.dirname(node.path))
                bom['metadata']['component']['bom-ref'] = bom['metadata']['component']['name'] + '@' + bom['metadata']['component']['version']
                dependencies = {
                    'ref': bom['metadata']['component']['bom-ref'],
                    'dependsOn': [],
                }
                for dependency in node.dependencies:
                    purl = get_purl(dependency.dst.remote, dependency.dst.ref)
                    dependencies['dependsOn'].append(str(purl))
                bom['dependencies'].append(dependencies)
            else:
                purl = get_purl(node.remote, node.ref)
                component = {
                    'bom-ref': str(purl),
                    'type': 'library',
                    'name': node.ref.name,
                    'version': str(node.ref.version),
                    'purl': str(purl),
                }
                if node.ref.user:
                    component['namespace'] = node.ref.user
                bom['components'].append(component)
                dependencies = {
                    'ref': component['bom-ref'],
                    'dependsOn': [],
                }
                for dependency in node.dependencies:
                    dep_purl = get_purl(dependency.dst.remote, dependency.dst.ref)
                    dependencies['dependsOn'].append(str(dep_purl))
                bom['dependencies'].append(dependencies)

        print(json.dumps(bom, indent=2))


def get_purl(remote, ref: RecipeReference):
    qualifiers = {
        'repository_url': 'localhost' if remote is None else remote.url,
    }
    if ref.user:
        qualifiers['channel'] = ref.channel
    purl = PackageURL(type='conan', namespace=ref.user, name=ref.name, version=str(ref.version), qualifiers=qualifiers)
    return purl


def main():
    parser = CycloneDXCommand.get_arg_parser()
    args = parser.parse_args()
    CycloneDXCommand(args).execute()


if __name__ == '__main__':
    main()
