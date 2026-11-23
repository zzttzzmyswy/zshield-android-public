# ZShield release rules.
#
# The only native code is libzshield.so, reached exclusively through
# top.zztweb.zshield.core.Native. JNI symbol names are derived from that class and its method
# names, so the class and its external declarations must survive R8 untouched.

-keep class top.zztweb.zshield.core.Native { *; }
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

# rustls-platform-verifier's Kotlin component is called from Rust through JNI only, which R8
# cannot see. Losing it breaks certificate validation at runtime.
-keep, includedescriptorclasses class org.rustls.platformverifier.** { *; }

# The HTTPS owner lookup: `top.zztweb.zshield.https.OwnerResolver.ownerUid` is called from Rust
# through JNI, so R8 sees no caller and would strip the class. Losing it makes every 443 connection
# report "unknown owner" and silently decrypt nothing — which is exactly what happened on the first
# device build of M3a.
-keep class top.zztweb.zshield.https.OwnerResolver { *; }

# Keep the service and activity names referenced from the manifest (defensive: AGP usually keeps
# these, but a renamed VpnService would silently stop the tunnel).
-keep class top.zztweb.zshield.vpn.ZShieldVpnService { *; }

# No reflection-based serialisation is used; nothing else needs to be kept.
