#!/usr/bin/env bash
# Generates a release signing key for local builds.
#
# Location (both outside the repository, per docs/DESIGN.md §5):
#   ~/.config/zshield/release.jks           key store (PKCS12)
#   ~/.config/zshield/keystore.properties   passwords + alias, mode 600
#
# `ZSHIELD_KEYSTORE_DIR` overrides that directory. The official release identity lives at the default
# location; a contributor who only wants to build for themselves points this at a directory of their
# own (`ZSHIELD_KEYSTORE_DIR=$HOME/.config/zshield-contributor scripts/gen-keystore.sh`), which keeps a throwaway
# key from ever being mistaken for — or written over — the official one.
#
# The password is random, so nothing has to be remembered by a human and nothing secret ever reaches
# the repository. Re-running does not overwrite an existing key store: losing it would make every
# future APK un-upgradable over the installed one.

set -euo pipefail

KEYSTORE_DIR="${ZSHIELD_KEYSTORE_DIR:-${HOME}/.config/zshield}"
KEYSTORE="${ZSHIELD_RELEASE_KEYSTORE:-${KEYSTORE_DIR}/release.jks}"
PROPERTIES="${ZSHIELD_KEYSTORE_PROPERTIES:-${KEYSTORE_DIR}/keystore.properties}"
ALIAS="zshield"
VALIDITY_DAYS=10000

JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk}"
KEYTOOL="${JAVA_HOME}/bin/keytool"
[ -x "$KEYTOOL" ] || KEYTOOL="$(command -v keytool || true)"
[ -n "$KEYTOOL" ] && [ -x "$KEYTOOL" ] || { echo "keytool not found (set JAVA_HOME)" >&2; exit 1; }

mkdir -p "$KEYSTORE_DIR"
chmod 700 "$KEYSTORE_DIR"

if [ -f "$KEYSTORE" ]; then
    echo "已存在签名密钥，保持不变: $KEYSTORE"
    exit 0
fi

PASSWORD="$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"

"$KEYTOOL" -genkeypair \
    -keystore "$KEYSTORE" \
    -storetype PKCS12 \
    -alias "$ALIAS" \
    -keyalg RSA \
    -keysize 4096 \
    -validity "$VALIDITY_DAYS" \
    -dname "CN=ZShield, O=ZShield, C=CN" \
    -storepass "$PASSWORD" \
    -keypass "$PASSWORD" \
    -noprompt >/dev/null

cat > "$PROPERTIES" <<EOF
storePassword=$PASSWORD
keyPassword=$PASSWORD
keyAlias=$ALIAS
storeFile=$KEYSTORE
EOF
chmod 600 "$PROPERTIES" "$KEYSTORE"

echo "已生成签名密钥:"
echo "  keystore:   $KEYSTORE"
echo "  properties: $PROPERTIES (mode 600)"
echo "  alias:      $ALIAS"
echo
echo "请自行备份 $KEYSTORE_DIR —— 丢失后已安装的 APK 无法升级。"
