#!/bin/bash
#
# Copyright 2011 Google Inc.
# Modifications Copyright 2022-2023 Aerleon Project Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Author: watson@google.com (Tony Watson)

rev=`svn up|awk '{print $3}'`
archive="aerleon-r"$rev"tgz"
filedir='./aerleon'

echo "Building: $archive"
find . -name \*.pyc -exec rm {} \;
pushd . > /dev/null
cd ..
tar -czf $archive --exclude-vcs $filedir
mv $archive $filedir
popd > /dev/null
ls -al $archive
echo "Done."

