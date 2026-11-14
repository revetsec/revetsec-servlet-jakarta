#!/usr/bin/env bash
# Copyright 2026 Revetware LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Installs the checksum-pinned Corretto 26 JDK used only for public Javadoc.
#
# Usage: install-pinned-corretto-linux-x64.sh <javadocJava> <runner-temp> <github-env> <evidence-file>

set -euo pipefail

if [[ $# -ne 4 ]]; then
	printf 'Usage: %s <javadocJava> <runner-temp> <github-env> <evidence-file>\n' "$0" >&2
	exit 64
fi

toolchain_name=$1
runner_temp=$2
github_env=$3
evidence_file=$4
for path in "$runner_temp" "$github_env" "$evidence_file"; do
	[[ "$path" == /* ]] || { printf 'Installer paths must be absolute.\n' >&2; exit 1; }
done

case "$toolchain_name" in
	javadocJava)
		expected_major=26
		environment_name=REVETSEC_JAVADOC_HOME
		java_version=26.0.2.1
		runtime_version=26.0.2.1+11-FR
		vendor_version=Corretto-26.0.2.11.1
		distribution=corretto
		archive=amazon-corretto-26.0.2.11.1-linux-x64.tar.gz
		archive_sha256=f61206891b8e1009b117eefe38784cf31b0a5cdb02fd2e023556f436b85dedaa
		distribution_url=https://corretto.aws/downloads/resources/26.0.2.11.1/amazon-corretto-26.0.2.11.1-linux-x64.tar.gz
		;;
	*)
		printf 'Unsupported Corretto toolchain: %s\n' "$toolchain_name" >&2
		exit 64
		;;
esac

distribution_version=${vendor_version#Corretto-}
[[ "$distribution" == corretto ]] || { printf 'Pinned Java distribution must be Corretto.\n' >&2; exit 1; }
[[ "$java_version" =~ ^${expected_major}\.0\.[0-9]+(\.[0-9]+)?$ ]] \
	|| { printf 'Invalid pinned Java version: %s\n' "$java_version" >&2; exit 1; }
[[ "$vendor_version" =~ ^Corretto-${expected_major}\.0\.[0-9]+\.[0-9]+\.[0-9]+$ ]] \
	|| { printf 'Invalid pinned Corretto build: %s\n' "$vendor_version" >&2; exit 1; }

IFS=. read -r release_major release_minor release_security release_build release_package \
	<<< "$distribution_version"
release_version_prefix="$release_major.$release_minor.$release_security"
[[ "$java_version" == "$release_version_prefix" \
		|| "$java_version" == "$release_version_prefix.$release_package" ]] \
	|| { printf 'Pinned Corretto version fields are inconsistent.\n' >&2; exit 1; }
[[ "$runtime_version" == "$java_version+$release_build-FR" && "$release_package" =~ ^[0-9]+$ ]] \
	|| { printf 'Pinned Corretto version fields are inconsistent.\n' >&2; exit 1; }

expected_archive="amazon-corretto-$distribution_version-linux-x64.tar.gz"
expected_url="https://corretto.aws/downloads/resources/$distribution_version/$expected_archive"
[[ "$archive" == "$expected_archive" ]] \
	|| { printf 'Pinned Corretto archive does not match its build.\n' >&2; exit 1; }
[[ "$archive_sha256" =~ ^[0-9a-f]{64}$ ]] \
	|| { printf 'Pinned Corretto SHA-256 is malformed.\n' >&2; exit 1; }
[[ "$distribution_url" == "$expected_url" ]] \
	|| { printf 'Pinned Corretto distribution URL is not canonical.\n' >&2; exit 1; }

staging_root="$runner_temp/revetsec-$toolchain_name-$distribution_version"
archive_path="$staging_root/$archive"
java_home="$staging_root/amazon-corretto-$distribution_version-linux-x64"
[[ ! -e "$staging_root" && ! -L "$staging_root" ]] \
	|| { printf 'Pinned Corretto staging directory already exists: %s\n' "$staging_root" >&2; exit 1; }
[[ ! -e "$evidence_file" && ! -L "$evidence_file" ]] \
	|| { printf 'Pinned Corretto evidence must be a create-new path.\n' >&2; exit 1; }

mkdir -p "$staging_root"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
	--retry 3 "$distribution_url" --output "$archive_path"
printf '%s  %s\n' "$archive_sha256" "$archive_path" | sha256sum --check --strict
tar -xzf "$archive_path" -C "$staging_root"

[[ -x "$java_home/bin/java" && -x "$java_home/bin/javac" && -x "$java_home/bin/javadoc" ]] \
	|| { printf 'Extracted Corretto JDK executables are missing.\n' >&2; exit 1; }

java_property() {
	"$java_home/bin/java" -XshowSettings:properties -version 2>&1 \
		| sed -n "s/^[[:space:]]*$1 = //p" | head -n 1
}

actual_version=$(java_property java.version)
actual_runtime_version=$(java_property java.runtime.version)
actual_vendor=$(java_property java.vendor)
actual_vendor_version=$(java_property java.vendor.version)
actual_javac_version=$("$java_home/bin/javac" -version 2>&1)
actual_javadoc_version=$("$java_home/bin/javadoc" --version 2>&1)
[[ "$actual_version" == "$java_version" \
		&& "$actual_runtime_version" == "$runtime_version" \
		&& "$actual_vendor" == "Amazon.com Inc." \
		&& "$actual_vendor_version" == "$vendor_version" \
		&& "$actual_javac_version" == "javac $java_version" \
		&& "$actual_javadoc_version" == "javadoc $java_version" ]] \
	|| { printf 'Extracted Corretto JDK identity does not match the reviewed pin.\n' >&2; exit 1; }

printf '%s=%s\n' "$environment_name" "$java_home" >> "$github_env"
printf 'distribution=%s\nversion=%s\nruntimeVersion=%s\nvendorVersion=%s\nurl=%s\narchive=%s\narchiveSha256=%s\n' \
	"$distribution" "$java_version" "$runtime_version" "$vendor_version" \
	"$distribution_url" "$archive" "$archive_sha256" > "$evidence_file"
printf 'Verified %s from %s.\n' "$vendor_version" "$archive"
