// Top-level build file. Versions of AGP/Kotlin are pinned here so the whole project (including
// scripts/build.sh) uses one toolchain. AGP 9 has built-in Kotlin support, so no Kotlin plugin is
// applied to the app module.
plugins {
    id("com.android.application") version "9.5.1" apply false
    // Compose compiler; its version must equal the Kotlin version AGP 9.5.1 bundles (2.2.10).
    id("org.jetbrains.kotlin.plugin.compose") version "2.2.10" apply false
}

// Version is read from `version.properties`, the single source of truth.
val versionProps = java.util.Properties().apply {
    rootProject.file("version.properties").inputStream().use { load(it) }
}
val versionName = versionProps.getProperty("versionName")
    ?: error("versionName missing from version.properties")
val versionCode = versionProps.getProperty("versionCode")?.toIntOrNull()
    ?: error("versionCode missing from version.properties")

// Exposed to :app through extra properties (read-only snapshot, evaluated once).
extra["zshieldVersionName"] = versionName
extra["zshieldVersionCode"] = versionCode

tasks.register("printVersion") {
    group = "help"
    description = "Prints the version read from version.properties."
    doLast { println("$versionName ($versionCode)") }
}
