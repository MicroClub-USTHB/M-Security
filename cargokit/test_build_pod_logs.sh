#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd "$(dirname "$0")" && pwd -P); repo_root=$(cd "$script_dir/.." && pwd -P)
scan_file() {
  local file=$1
  local status
  if ! [[ -f $file ]]; then
    printf 'Missing Apple build input: %s\n' "$file" >&2
    return 2
  fi
  if LC_ALL=C perl - "$file" <<'PERL'
use strict; use warnings;
open my $input, '<', $ARGV[0] or exit 2;
local $/; my $text = <$input>; defined $text or exit 2;
$text =~ s/\\\r?\n/ /g;
for my $line (split /\n/, $text) {
  for my $command (split /[;&|]+/, $line) {
    $command =~ s/^\s+|\s+$//g;
    $command =~ s/\s+#.*$//;
    if ($command =~ /^set\s+(.*)$/) {
      exit 1 if $1 =~ /(?:^|\s)(?:-[A-Za-z]*x[A-Za-z]*|-o\s+xtrace)(?:\s|$)/;
    }
    next unless $command =~ m{^(?:/usr/bin/)?(env|printenv)\b(.*)$};
    my ($utility, $rest) = ($1, $2);
    $rest =~ s/^\s+|\s+$//g;
    if ($utility eq 'printenv') {
      $rest =~ s/^--\s*//;
      exit 1 if $rest eq '' || $rest =~ /^(?:\d*(?:>>?|<<?|<>|>&|<&)\s*\S*\s*)+$/;
      next;
    }
    while ($rest ne '') {
      exit 1 if $rest =~ /^-S/;
      next if $rest =~ s/^[A-Za-z_][A-Za-z0-9_]*=\S*\s*//;
      next if $rest =~ s/^\d*(?:>>?|<<?|<>|>&|<&)\s*\S*\s*//;
      next if $rest =~ s/^(?:-u(?:\s+\S+|\S+)|--unset(?:=|\s+)\S+|-P(?:\s+\S+|\S+)|-i|--ignore-environment|--)\s*//;
      last;
    }
    exit 1 if $rest eq '' || $rest =~ m{^(?:/usr/bin/)?(?:env|printenv)(?:\s|$)};
  }
}
exit 0;
PERL
  then return 0; else status=$?; fi
  if [[ $status -eq 1 ]]; then
    printf 'Unsafe environment output or shell tracing in %s\n' "$file" >&2
  else printf 'Unable to scan Apple build input: %s\n' "$file" >&2; fi
  return "$status"
}
check_static() { scan_file "$repo_root/ios/m_security.podspec"; scan_file "$repo_root/macos/m_security.podspec"
  scan_file "$repo_root/cargokit/build_pod.sh"; scan_file "$repo_root/cargokit/run_build_tool.sh"
}
check_mutation() (
  local fixture_dir= fixture mutation status
  cleanup_fixture() {
    local original_status=$? cleanup_status=0
    trap - EXIT HUP INT TERM
    if [[ -n $fixture_dir ]] && ! rm -rf -- "$fixture_dir"; then
      printf 'Unable to remove static-check fixtures: %s\n' "$fixture_dir" >&2
      cleanup_status=1
    fi
    if [[ $original_status -ne 0 ]]; then exit "$original_status"; fi
    exit "$cleanup_status"
  }
  expect_violation() {
    printf '%b\n' "$1" > "$fixture"
    if scan_file "$fixture" >/dev/null 2>&1; then status=0; else status=$?; fi
    if [[ $status -eq 1 ]]; then return 0; fi
    printf 'Static Apple build-log mutation returned status %s: %s\n' \
      "$status" "$1" >&2
    return 1
  }
  trap cleanup_fixture EXIT
  trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM
  fixture_dir=$(mktemp -d)
  fixture="$fixture_dir/build_pod.sh"
  printf 'env printf "safe keyed utility\\n"\n' > "$fixture"
  if ! scan_file "$fixture"; then
    printf 'Static Apple build-log check rejected a safe command\n' >&2
    return 1
  fi
  for mutation in '  env' '/usr/bin/env' ' /usr/bin/printenv' 'set -e -x' 'set -o xtrace' \
    'env NAME=value 2> errors > output' 'env --' 'printenv --' \
    'env -u BUILD_TOKEN_CANARY -u BUILD_SIGNING_CANARY -u BUILD_GENERIC_CANARY' 'env -uBUILD_TOKEN_CANARY -uBUILD_SIGNING_CANARY -uBUILD_GENERIC_CANARY' \
    'env -u BUILD_TOKEN_CANARY -u BUILD_SIGNING_CANARY -u BUILD_GENERIC_CANARY printenv' "/usr/bin/env -S 'printenv'" \
    'env -Senv' 'env -Sprintenv' 'env -S env' 'env -S printenv' "env -S 'env -u NEVER_SET'" "env -S '-u NEVER_SET'" \
    'env -P /usr/bin env' 'env -P /usr/bin printenv' 'env -P/usr/bin env' 'env -P/usr/bin printenv'
  do
    expect_violation "$mutation"
  done
  expect_violation 'env \\\n  > output'
)
scan_raw() {
  local sentinel=$1
  shift
  local file status
  for file in "$@"; do
    if LC_ALL=C grep -Fq -- "$sentinel" "$file"; then
      printf 'Raw Apple build output contains its environment sentinel: %s\n' \
        "$file" >&2
      return 1
    else status=$?; fi
    if [[ $status -ne 1 ]]; then
      printf 'Unable to scan raw Apple build output: %s\n' "$file" >&2
      return 2
    fi
  done
}
require_text() {
  local description=$1
  local text=$2
  shift 2
  local found=0 file status
  for file in "$@"; do
    if LC_ALL=C grep -Fq -- "$text" "$file"; then
      found=1; continue
    else status=$?; fi
    if [[ $status -ne 1 ]]; then
      printf 'Unable to inspect Apple build output for %s: %s\n' \
        "$description" "$file" >&2
      return 2
    fi
  done
  if [[ $found -eq 1 ]]; then return 0; fi
  printf 'Missing %s in Apple build output\n' "$description" >&2
  return 1
}
redact_log() {
  local source=$1 destination=$2 raw_dir=$3 selected_temp=$4
  REDACT_REPO=$repo_root REDACT_RAW=$raw_dir REDACT_TEMP=$selected_temp \
  REDACT_RUNNER_TEMP=${RUNNER_TEMP:-} REDACT_TMPDIR=${TMPDIR:-} \
  REDACT_HOME=${HOME:-} \
    perl -e '
      use bytes; local $/; my $data = <STDIN>;
      die "unable to read raw log\n" if !defined $data;
      for my $item (
        ["REDACT_RAW", "<raw-dir>"], ["REDACT_REPO", "<repo-root>"],
        ["REDACT_RUNNER_TEMP", "<runner-temp>"], ["REDACT_TMPDIR", "<tmpdir>"],
        ["REDACT_TEMP", "<selected-temp>"], ["REDACT_HOME", "<home>"],
      ) {
        my $value = $ENV{$item->[0]};
        next if !defined($value) || $value eq "";
        $data =~ s/\Q$value\E/$item->[1]/g;
      }
      print $data or die "unable to write redacted log\n";
    ' < "$source" > "$destination"
}
run_build_checks() (
  local output_dir=$1 selected_temp=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
  local raw_dir= output_reserved=0 output_complete=0
  local success_status failure_status arch sentinel library revision
  cleanup() {
    local original_status=$? cleanup_status=0
    trap - EXIT
    if [[ -n $raw_dir ]] && ! rm -rf "$raw_dir"; then
      printf 'Unable to remove raw Apple build logs: %s\n' "$raw_dir" >&2
      cleanup_status=1
    fi
    if [[ $output_reserved -eq 1 &&
      ( $output_complete -eq 0 || $cleanup_status -ne 0 ) ]] &&
      ! rm -rf "$output_dir"; then
      printf 'Unable to remove incomplete retained logs: %s\n' "$output_dir" >&2
      cleanup_status=1
    fi
    if [[ $original_status -ne 0 ]]; then exit "$original_status"; fi
    exit "$cleanup_status"
  }
  trap cleanup EXIT
  if [[ $(uname -s) != Darwin ]]; then
    printf 'Apple build-log checks require macOS\n' >&2; return 1
  fi
  if ! mkdir "$output_dir"; then
    printf 'Unable to reserve retained log directory: %s\n' "$output_dir" >&2; return 1
  fi
  output_reserved=1
  raw_dir=$(mktemp -d "$selected_temp/apple-build-logs.XXXXXX")
  arch=$(uname -m)
  if [[ $arch != arm64 && $arch != x86_64 ]]; then
    printf 'Unsupported macOS build architecture: %s\n' "$arch" >&2; return 1
  fi
  sentinel=$(uuidgen | tr -d '-')
  mkdir -p "$raw_dir/target" "$raw_dir/output/m_security" \
    "$raw_dir/obj/XCBuildData" "$raw_dir/products"
  export BUILD_TOKEN_CANARY="token-$sentinel" \
    BUILD_SIGNING_CANARY="signing-$sentinel" BUILD_GENERIC_CANARY="generic-$sentinel"
  export PLATFORM_NAME=macosx ARCHS=$arch CONFIGURATION=Debug PRODUCT_NAME=m_security
  export PODS_TARGET_SRCROOT="$repo_root/macos" TARGET_TEMP_DIR="$raw_dir/target"
  export PODS_CONFIGURATION_BUILD_DIR="$raw_dir/output"
  export SRCROOT="$repo_root/example/macos" PODS_ROOT="$repo_root/example/macos/Pods"
  export OBJROOT="$raw_dir/obj" BUILT_PRODUCTS_DIR="$raw_dir/products"
  export EXECUTABLE_PATH=m_security.framework/Versions/A/m_security
  set +e
  sh "$repo_root/cargokit/build_pod.sh" ../rust m_security \
    >"$raw_dir/success.stdout" 2>"$raw_dir/success.stderr"
  success_status=$?; set -e
  scan_raw "$sentinel" "$raw_dir/success.stdout" "$raw_dir/success.stderr"
  if [[ $success_status -ne 0 ]]; then
    printf 'Expected Apple build success, got status %s\n' "$success_status" >&2; return 1; fi
  require_text 'safe platform diagnostic' 'Cargokit Apple build: platform=macosx' \
    "$raw_dir/success.stdout" "$raw_dir/success.stderr"
  library="$PODS_CONFIGURATION_BUILD_DIR/$PRODUCT_NAME/libm_security.a"
  if [[ ! -s $library ]]; then
    printf 'Apple build did not produce a nonempty libm_security.a\n' >&2; return 1; fi
  set +e
  CARGOKIT_VERBOSE=1 \
  RUSTFLAGS='-C definitely-not-a-codegen-option=yes' \
    sh "$repo_root/cargokit/build_pod.sh" ../rust m_security \
    >"$raw_dir/failure.stdout" 2>"$raw_dir/failure.stderr"
  failure_status=$?; set -e
  scan_raw "$sentinel" "$raw_dir/failure.stdout" "$raw_dir/failure.stderr"
  if [[ $failure_status -eq 0 ]]; then
    printf 'Expected forced Apple build failure\n' >&2; return 1; fi
  require_text 'injected compiler failure' 'definitely-not-a-codegen-option' \
    "$raw_dir/failure.stdout" "$raw_dir/failure.stderr"
  require_text 'compiler error' 'error: unknown codegen option:' \
    "$raw_dir/failure.stdout" "$raw_dir/failure.stderr"
  require_text 'verbose build command' \
    'FINER: Running command rustup run stable cargo build' \
    "$raw_dir/failure.stdout" "$raw_dir/failure.stderr"
  if ! revision=$(git -C "$repo_root" rev-parse HEAD) ||
    [[ -z $revision ]]; then
    printf 'Unable to identify the source revision\n' >&2; return 1
  fi
  redact_log "$raw_dir/success.stdout" "$output_dir/success.stdout" "$raw_dir" "$selected_temp"
  redact_log "$raw_dir/success.stderr" "$output_dir/success.stderr" "$raw_dir" "$selected_temp"
  redact_log "$raw_dir/failure.stdout" "$output_dir/failure.stdout" "$raw_dir" "$selected_temp"
  redact_log "$raw_dir/failure.stderr" "$output_dir/failure.stderr" "$raw_dir" "$selected_temp"
  {
    printf 'revision=%s\n' "$revision"
    printf 'sentinel_source=runtime_uuid\n'
    printf 'success_status=%s\n' "$success_status"
    printf 'success_library=nonempty\n'
    printf 'failure_status=%s\n' "$failure_status"
    printf 'failure_marker=present\n'
    printf 'failure_verbose=present\n'
    printf 'raw_stdout_stderr_scan=pass\n'
  } > "$output_dir/result.txt"
  output_complete=1
)
case ${1:-} in
  static) check_static; check_mutation ;;
  build)
    if [[ $# -ne 2 ]]; then
      printf 'Usage: %s build <output-directory>\n' "$0" >&2; exit 2
    fi
    check_static; check_mutation; run_build_checks "$2"
    ;;
  *)
    printf 'Usage: %s {static|build <output-directory>}\n' "$0" >&2; exit 2
    ;;
esac
