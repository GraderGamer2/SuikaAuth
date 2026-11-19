#!/usr/bin/env bash
set -euo pipefail

# Keep application source free of diagnostics and logging integrations.
rust_pattern='(^|[^[:alnum:]_])(println|eprintln|print|eprint|dbg)![[:space:]]*\(|(^|[^[:alnum:]_])(log|tracing)::|tracing_subscriber|env_logger|simple_logger|android_logger|opentelemetry|sentry|crashlytics'
jvm_pattern='android\.util\.Log|(^|[^[:alnum:]_])Log\.[divewt][[:space:]]*\(|System\.(out|err)|printStackTrace[[:space:]]*\(|java\.util\.logging|FirebaseCrashlytics|Sentry'

failed=0
if grep -RInE --include='*.rs' "$rust_pattern" apps/linux/src crates android/native/src; then
  failed=1
fi
if grep -RInE --include='*.kt' --include='*.java' "$jvm_pattern" android/app/src/main/java; then
  failed=1
fi

if [[ "$failed" -ne 0 ]]; then
  printf '%s\n' "Application logging/diagnostic code is not permitted."
  exit 1
fi
