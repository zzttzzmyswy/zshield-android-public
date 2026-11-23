#!/usr/bin/env bash
# ZShield build entry point.
#
# Usage: scripts/build.sh [debug|release|clean]
#
# The first step of every build is deleting previous artifacts: only the outputs of the current
# build may exist in `app/build/outputs/`, `dist/` and `app/src/main/jniLibs/`. That is what makes
# "run it twice and you still have exactly one APK" true.
#
# Version comes from `version.properties` (the single source of truth). A release build also
# enforces the 10 MB budget from docs/DESIGN.md §1 and prints every artifact's size.

set -euo pipefail

log()  { printf '\n=== %s\n' "$*"; }
fail() { printf '\n!!! %s\n' "$*" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# The Android SDK is found the way every other Gradle project finds it: an explicit
# `ANDROID_SDK_ROOT`/`ANDROID_HOME` wins, then `local.properties` (`sdk.dir`, what Android Studio
# writes and what `.gitignore` keeps out of the repository), then the conventional per-user
# locations. No absolute path of one particular machine belongs here.
default_android_sdk() {
    if [ -n "${ANDROID_SDK_ROOT:-}" ]; then printf '%s' "$ANDROID_SDK_ROOT"; return 0; fi
    if [ -n "${ANDROID_HOME:-}" ]; then printf '%s' "$ANDROID_HOME"; return 0; fi
    if [ -f local.properties ]; then
        local dir
        dir="$(sed -n 's/^sdk\.dir=//p' local.properties | head -1)"
        if [ -n "$dir" ]; then printf '%s' "$dir"; return 0; fi
    fi
    local candidate
    for candidate in "$HOME/Android/Sdk" "$HOME/android-sdk" "/usr/local/lib/android/sdk" \
                     "/opt/android-sdk" "/usr/lib/android-sdk"; do
        if [ -d "$candidate" ]; then printf '%s' "$candidate"; return 0; fi
    done
    return 1
}

ANDROID_SDK="$(default_android_sdk || true)"
[ -n "$ANDROID_SDK" ] || fail "找不到 Android SDK：设置 ANDROID_SDK_ROOT，或在 local.properties 写 sdk.dir"
export ANDROID_SDK_ROOT="$ANDROID_SDK"
export ANDROID_HOME="$ANDROID_SDK"
# The NDK version is pinned in `app/build.gradle.kts` (`ndkVersion`); this only has to point the
# `cargo ndk` invocation at the same installation.
NDK_VERSION="$(grep -E 'ndkVersionUsed *= *"' app/build.gradle.kts | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
[ -n "$NDK_VERSION" ] || fail "app/build.gradle.kts 里找不到 ndkVersionUsed"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_SDK/ndk/$NDK_VERSION}"
# JDK 17 is the compile target (docs/DESIGN.md 固定决策 3). An explicit JAVA_HOME wins; otherwise the
# first JDK 17 on the machine, then whatever `java` resolves to.
if [ -z "${JAVA_HOME:-}" ]; then
    for candidate in /usr/lib/jvm/java-17-openjdk /usr/lib/jvm/java-17-openjdk-amd64 \
                     /Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home; do
        if [ -x "$candidate/bin/javac" ]; then JAVA_HOME="$candidate"; break; fi
    done
fi
export JAVA_HOME="${JAVA_HOME:-}"
export PATH="$HOME/.cargo/bin:${JAVA_HOME:+$JAVA_HOME/bin:}$PATH"

# ---------------------------------------------------------------------------------------------
# Build paths must not end up in the shipped native library
# ---------------------------------------------------------------------------------------------
# Rust embeds the absolute source path of every file whose code can panic, plus the registry and
# toolchain paths, as `core/src/…`, `/home/<user>/.cargo/registry/…` and `/home/<user>/.rustup/…`.
# A release APK is a public artifact; the build machine's layout (user name, workspace path) is not
# part of it. `--remap-path-prefix` rewrites all of them to fixed, meaningless prefixes, so these paths
# are independent of the local checkout.
#
# The order matters and is not intuitive: `rustc` applies the **last** matching prefix, not the
# longest, so the general `$HOME` rule comes first and the specific ones after it.
#
# Each rule is emitted as **one line**, because the caller joins them into the `\x1f`-separated
# `CARGO_ENCODED_RUSTFLAGS` form where one flag is one element. That form is what makes a checkout
# under a path containing a space work: `RUSTFLAGS` is split on whitespace by cargo, so a rule like
# `--remap-path-prefix=/home/me/My Project/core=/zshield` would arrive as two broken flags.
remap_rustflags() {
    local repo_root="$1"
    printf '%s\n' "--remap-path-prefix=$HOME=/home/build"
    printf '%s\n' "--remap-path-prefix=$HOME/.cargo=/cargo"
    printf '%s\n' "--remap-path-prefix=$HOME/.rustup=/rustup"
    # The repository's parent first, then the repository itself: the second rule is the more specific
    # of the two and, being last, is the one `rustc` applies to paths inside the checkout. Distinct
    # targets keep a sibling directory from looking like the project. A repository sitting directly
    # in `/` has no useful parent rule, and `--remap-path-prefix=/=…` would rewrite every absolute
    # path in the build.
    local parent
    parent="$(dirname "$repo_root")"
    if [ "$parent" != "/" ] && [ "$parent" != "." ]; then
        printf '%s\n' "--remap-path-prefix=$parent=/build"
    fi
    printf '%s\n' "--remap-path-prefix=$repo_root=/zshield"
}

# The flags travel in `CARGO_ENCODED_RUSTFLAGS`, not `RUSTFLAGS`.
#
# Two separate reasons, both measured rather than assumed:
#   * `CARGO_ENCODED_RUSTFLAGS` **overrides** `RUSTFLAGS` outright. An inherited one would silently
#     discard the remapping and put the build machine's paths back into the shipped library — the
#     exact regression this block exists to prevent. So an inherited one is not unset; it is
#     preserved with Cargo’s normal precedence over `RUSTFLAGS`.
#   * the encoded form is `\x1f`-separated with one flag per element, so a workspace path that
#     contains a space survives intact. In `RUSTFLAGS` it would be split in two and the build would
#     fail with an unhelpful rustc error.
#
# A caller's own flags are kept, in their original order, with the remapping appended.
merge_rustflags() {
    local sep=$'\x1f' out=() flag
    if [ -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]; then
        # Already encoded: split on its own separator, never on whitespace (an element may contain
        # spaces by design).
        while IFS= read -r -d "$sep" flag; do
            [ -n "$flag" ] && out+=("$flag")
        done <<<"${CARGO_ENCODED_RUSTFLAGS}${sep}"
    elif [ -n "${RUSTFLAGS:-}" ]; then
        # `RUSTFLAGS` is whitespace-separated by definition, so this is exactly how cargo would have
        # read it; re-emitting it element-wise is what stops a later space from re-splitting it.
        read -r -a out <<<"$RUSTFLAGS"
    fi
    while IFS= read -r flag; do
        [ -n "$flag" ] && out+=("$flag")
    done < <(remap_rustflags "$REPO_ROOT")

    local joined=""
    for flag in "${out[@]}"; do
        joined="${joined:+$joined$sep}$flag"
    done
    printf '%s' "$joined"
}

CARGO_ENCODED_RUSTFLAGS="$(merge_rustflags)"
export CARGO_ENCODED_RUSTFLAGS
# Left in place if the caller set it, but it no longer decides anything: cargo prefers the encoded
# variable, and the merged value above already contains whatever this held.


# Release APK size budget (docs/DESIGN.md §1).
MAX_RELEASE_APK_BYTES=$((10 * 1024 * 1024))

MODE="${1:-debug}"

# ---------------------------------------------------------------------------------------------
# Version (read here so it can be printed and used for the artifact name)
# ---------------------------------------------------------------------------------------------
read_version() {
    local key="$1"
    grep -E "^${key}=" version.properties | head -1 | cut -d= -f2 | tr -d '[:space:]'
}

VERSION_NAME="$(read_version versionName)"
VERSION_CODE="$(read_version versionCode)"
[ -n "$VERSION_NAME" ] || fail "versionName missing from version.properties"
[ -n "$VERSION_CODE" ] || fail "versionCode missing from version.properties"

# ---------------------------------------------------------------------------------------------
# Cleanup: always the first thing a build does
# ---------------------------------------------------------------------------------------------
clean_outputs() {
    log "删除旧产物"
    rm -rf app/build/outputs dist
    find app/src/main/jniLibs -type f -name '*.so' -delete 2>/dev/null || true
    # Empty per-ABI directories left behind would otherwise be packaged.
    find app/src/main/jniLibs -mindepth 1 -type d -empty -delete 2>/dev/null || true
    mkdir -p dist
    echo "removed: app/build/outputs dist app/src/main/jniLibs/**/*.so"
}

gradle_cmd() {
    if [ -x ./gradlew ]; then
        ./gradlew --no-daemon "$@"
    else
        gradle --no-daemon "$@"
    fi
}

# ---------------------------------------------------------------------------------------------
# Signing material
# ---------------------------------------------------------------------------------------------
# The release identity lives outside the repository (`docs/DESIGN.md` §5) and is *never* created here
# on demand: an APK signed with a freshly generated key cannot upgrade anything already installed and
# is not the identity testers and users hold. So a release build requires the material to exist and
# fails with instructions otherwise.
#
# `ZSHIELD_KEYSTORE_DIR` (or the two explicit file variables) points the build at a different set of
# files. That is what lets a contributor verify the whole release pipeline with a throwaway key of
# their own without touching — or silently replacing — the official one. The three variables are
# exported so Gradle (`app/build.gradle.kts`) resolves exactly the same files this script checked.
KEYSTORE_DIR="${ZSHIELD_KEYSTORE_DIR:-$HOME/.config/zshield}"
RELEASE_KEYSTORE="${ZSHIELD_RELEASE_KEYSTORE:-$KEYSTORE_DIR/release.jks}"
KEYSTORE_PROPERTIES="${ZSHIELD_KEYSTORE_PROPERTIES:-$KEYSTORE_DIR/keystore.properties}"
export ZSHIELD_KEYSTORE_DIR="$KEYSTORE_DIR"
export ZSHIELD_RELEASE_KEYSTORE="$RELEASE_KEYSTORE"
export ZSHIELD_KEYSTORE_PROPERTIES="$KEYSTORE_PROPERTIES"

require_keystore() {
    if [ -f "$RELEASE_KEYSTORE" ] && [ -f "$KEYSTORE_PROPERTIES" ]; then
        return 0
    fi
    cat >&2 <<EOF

!!! release 签名材料不存在，构建中止
    keystore:   $RELEASE_KEYSTORE
    properties: $KEYSTORE_PROPERTIES

release APK 必须用固定的官方签名身份，否则已安装的版本无法覆盖升级。本项目不会在构建时
自动生成新密钥来顶替它。两条路径任选其一：

  1. 使用官方签名材料：把 release.jks 与 keystore.properties 放到上述位置（或设置
     ZSHIELD_KEYSTORE_DIR 指向它们所在的目录）。
  2. 仅为自己验证构建流程：生成一次性密钥到隔离目录，并显式指向它 —— 这样构建出的 APK
     属于你自己的身份，不能覆盖官方安装包：

         ZSHIELD_KEYSTORE_DIR="\$HOME/.config/zshield-contributor" scripts/gen-keystore.sh
         ZSHIELD_KEYSTORE_DIR="\$HOME/.config/zshield-contributor" scripts/build.sh release
EOF
    exit 1
}

# ---------------------------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------------------------
human_size() {
    local bytes="$1"
    if [ "$bytes" -ge $((1024 * 1024)) ]; then
        awk -v b="$bytes" 'BEGIN { printf "%.2f MB", b / 1048576 }'
    elif [ "$bytes" -ge 1024 ]; then
        awk -v b="$bytes" 'BEGIN { printf "%.1f KB", b / 1024 }'
    else
        printf '%d B' "$bytes"
    fi
}

report_apk() {
    local apk="$1"
    local bytes
    bytes=$(stat -c%s "$apk")
    printf 'APK  %s  %s (%d bytes)\n' "$(basename "$apk")" "$(human_size "$bytes")" "$bytes"
    # Per-ABI .so sizes, straight out of the package.
    if command -v unzip >/dev/null 2>&1; then
        unzip -l "$apk" 'lib/*/*.so' 2>/dev/null | awk '
            $4 ~ /^lib\// { printf "  so  %-40s %10d bytes (%.2f MB)\n", $4, $1, $1/1048576 }
        '
    fi
}

# ---------------------------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------------------------
case "$MODE" in
    clean)
        log "clean: gradle clean + cargo clean"
        gradle_cmd clean || true
        (cd core && cargo clean)
        rm -rf app/build dist app/src/main/jniLibs
        echo "clean 完成"
        ;;
    debug)
        clean_outputs
        log "构建 debug (versionName=$VERSION_NAME versionCode=$VERSION_CODE)"
        gradle_cmd :app:assembleDebug
        apk="$(find app/build/outputs/apk/debug -maxdepth 1 -name '*.apk' | head -1)"
        [ -n "$apk" ] || fail "debug APK 未生成"
        target="dist/zshield-${VERSION_NAME}-debug.apk"
        cp "$apk" "$target"
        log "产物"
        report_apk "$target"
        echo "dist: $target ($(human_size "$(stat -c%s "$target")"))"
        ;;
    release)
        # The keystore check comes *before* the cleanup: a build that cannot be signed must not
        # destroy the previous release artifact on its way to failing.
        require_keystore
        clean_outputs
        log "构建 release (versionName=$VERSION_NAME versionCode=$VERSION_CODE)"
        # Lint runs *before* packaging (MYS-2716 §4): an error-severity finding must fail the build
        # here, not after a 7 MB APK has already been assembled and copied to `dist/`. `lintRelease`
        # (not `lintDebug`) is the relevant variant, because shrinking, the release manifest merge and
        # the arm64-only native set are what the shipped artifact actually contains.
        log "静态检查 (lintRelease)"
        gradle_cmd :app:lintRelease
        echo "lintRelease 通过（0 error）"
        gradle_cmd :app:assembleRelease
        apk="$(find app/build/outputs/apk/release -maxdepth 1 -name '*.apk' ! -name '*unsigned*' | head -1)"
        [ -n "$apk" ] || fail "release APK 未生成（或只有 unsigned 产物）"
        target="dist/zshield-${VERSION_NAME}-release.apk"
        cp "$apk" "$target"
        log "产物"
        report_apk "$target"
        bytes=$(stat -c%s "$target")
        if [ "$bytes" -gt "$MAX_RELEASE_APK_BYTES" ]; then
            fail "release APK $(human_size "$bytes") 超过预算 $(human_size $MAX_RELEASE_APK_BYTES)（docs/DESIGN.md §1）"
        fi
        echo "尺寸检查通过：$(human_size "$bytes") ≤ $(human_size "$MAX_RELEASE_APK_BYTES")"
        log "dist 内容"
        ls -la dist
        ;;
    *)
        fail "未知模式 '$MODE'（支持 debug | release | clean）"
        ;;
esac
