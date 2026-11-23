import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

// ---------------------------------------------------------------------------------------------
// Version (single source of truth: ../version.properties)
// ---------------------------------------------------------------------------------------------
val versionPropsFile = rootProject.file("version.properties")
val versionProps = Properties().apply { versionPropsFile.inputStream().use { load(it) } }
val zshieldVersionName: String = versionProps.getProperty("versionName")
    ?: error("versionName missing from version.properties")
val zshieldVersionCode: Int = versionProps.getProperty("versionCode")?.toIntOrNull()
    ?: error("versionCode missing from version.properties")

// ---------------------------------------------------------------------------------------------
// Rust core: the .so is produced by cargo-ndk and consumed from src/main/jniLibs.
// ---------------------------------------------------------------------------------------------
val coreDir = rootProject.layout.projectDirectory.dir("core")
val jniLibsDir = layout.projectDirectory.dir("src/main/jniLibs")
val ndkVersionUsed = "28.2.13676358"

/** ABIs built for each build type. Release ships arm64 only (size budget); debug adds an emulator ABI. */
val releaseAbis = listOf("arm64-v8a")
val debugAbis = listOf("arm64-v8a", "x86_64")

fun cargoNdkTaskName(buildType: String) =
    "buildRustCore" + buildType.replaceFirstChar { it.uppercase() }

/**
 * Registers one `cargo ndk` build task per build type. The task writes the .so files straight into
 * `app/src/main/jniLibs/<abi>/` (gitignored), which is what the Android packaging step reads.
 */
fun registerRustBuildTask(buildType: String, abis: List<String>, release: Boolean) {
    val taskName = cargoNdkTaskName(buildType)
    tasks.register<Exec>(taskName) {
        group = "build"
        description = "Builds libzshield.so for $buildType (${abis.joinToString()}) with cargo-ndk."
        workingDir = coreDir.asFile
        val ndkHome = androidComponents.sdkComponents.ndkDirectory.get().asFile
        environment("ANDROID_NDK_HOME", ndkHome.absolutePath)
        environment("ZSHIELD_VERSION", zshieldVersionName)
        // cargo lives in ~/.cargo/bin, which is not always on the PATH Gradle inherits.
        val cargoBin = File(System.getProperty("user.home"), ".cargo/bin")
        environment(
            "PATH",
            cargoBin.absolutePath + File.pathSeparator + (System.getenv("PATH") ?: "")
        )
        val args = mutableListOf("cargo", "ndk")
        abis.forEach { abi -> args.addAll(listOf("-t", abi)) }
        args.addAll(listOf("-o", jniLibsDir.asFile.absolutePath, "build"))
        if (release) args.add("--release")
        commandLine(args)
        inputs.dir(coreDir.dir("src"))
        inputs.file(coreDir.file("Cargo.toml"))
        inputs.file(coreDir.file("Cargo.lock"))
        // Declare the .so outputs rather than the whole directory: the directory is also where old
        // artifacts are deleted from, so tracking it would make every build look dirty.
        outputs.files(abis.map { abi -> jniLibsDir.file("$abi/libzshield.so") })
    }
}

registerRustBuildTask("debug", debugAbis, release = false)
registerRustBuildTask("release", releaseAbis, release = true)

// ---------------------------------------------------------------------------------------------
// Signing (never in the repository)
// ---------------------------------------------------------------------------------------------
// `ZSHIELD_KEYSTORE_DIR` points both files at another directory, which is how a contributor builds a
// throwaway-signed APK for their own device without touching the official identity (scripts/build.sh
// documents the same two variables).
val keystoreDir: File = System.getenv("ZSHIELD_KEYSTORE_DIR")?.let(::File)
    ?: File(System.getProperty("user.home"), ".config/zshield")
val keystorePropertiesFile: File = System.getenv("ZSHIELD_KEYSTORE_PROPERTIES")?.let(::File)
    ?: File(keystoreDir, "keystore.properties")
val releaseKeystoreFile: File = System.getenv("ZSHIELD_RELEASE_KEYSTORE")?.let(::File)
    ?: File(keystoreDir, "release.jks")

android {
    namespace = "top.zztweb.zshield"
    compileSdk = 36
    ndkVersion = ndkVersionUsed

    defaultConfig {
        applicationId = "top.zztweb.zshield"
        minSdk = 28
        targetSdk = 36
        versionCode = zshieldVersionCode
        versionName = zshieldVersionName
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
            isMinifyEnabled = false
            ndk {
                abiFilters.clear()
                abiFilters.addAll(debugAbis)
            }
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Release ships arm64-v8a only, per the 10 MB budget in docs/DESIGN.md §1.
            ndk {
                abiFilters.clear()
                abiFilters.addAll(releaseAbis)
            }
            signingConfig = if (keystorePropertiesFile.exists() && releaseKeystoreFile.exists()) {
                signingConfigs.create("release") {
                    val props = Properties().apply {
                        keystorePropertiesFile.inputStream().use { load(it) }
                    }
                    storeFile = releaseKeystoreFile
                    storePassword = props.getProperty("storePassword")
                    keyAlias = props.getProperty("keyAlias")
                    keyPassword = props.getProperty("keyPassword")
                }
            } else {
                // `scripts/build.sh release` requires the material to exist and stops otherwise; an
                // unsigned APK that reaches a device cannot be installed over anything, so say so
                // loudly rather than producing one that looks fine.
                logger.lifecycle(
                    "ZShield: release signing material not found ($keystorePropertiesFile, " +
                        "$releaseKeystoreFile); release APK will be unsigned."
                )
                null
            }
        }
    }

    androidResources {
        localeFilters += listOf("en", "zh")
    }

    packaging {
        jniLibs {
            useLegacyPackaging = false
            // Only the core is native; anything else is an accident worth failing on.
        }
        resources {
            excludes += setOf(
                "META-INF/*.kotlin_module",
                "META-INF/DEPENDENCIES",
                "META-INF/LICENSE*",
                "META-INF/NOTICE*",
                "META-INF/AL2.0",
                "META-INF/LGPL2.1",
                "kotlin/**",
                "DebugProbesKt.bin",
            )
        }
    }

    buildFeatures {
        buildConfig = true
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
        // `android.util.Log` is a stub in local unit tests; the filters package logs there, so
        // returning the default value keeps those code paths testable on the JVM.
        unitTests.isReturnDefaultValues = true
    }

    lint {
        warningsAsErrors = false
        abortOnError = true
        // The app intentionally ships without an app icon in M0 (the UI task adds branding).
        disable += setOf("MissingApplicationIcon")
    }
}

// Hook the Rust build in front of each variant's native-library packaging. The cargo-ndk task
// writes straight into `src/main/jniLibs`, so the only thing Gradle needs is an ordering
// dependency from the merge tasks to the matching build-type task.
androidComponents {
    onVariants { variant ->
        val buildType = variant.buildType ?: return@onVariants
        val rustTask = cargoNdkTaskName(buildType)
        val cap = variant.name.replaceFirstChar { it.uppercase() }
        tasks.matching {
            it.name == "merge${cap}JniLibFolders" || it.name == "merge${cap}NativeLibs"
        }.configureEach {
            dependsOn(rustTask)
        }
    }
}

// ---------------------------------------------------------------------------------------------
// rustls-platform-verifier: its Kotlin component version must equal the crate version in
// core/Cargo.lock, which is resolved here at configuration time.
// ---------------------------------------------------------------------------------------------
abstract class RustlsVerifierVersion : ValueSource<String, RustlsVerifierVersion.Params> {
    interface Params : ValueSourceParameters {
        val lockFile: RegularFileProperty
    }

    override fun obtain(): String {
        val lock = parameters.lockFile.get().asFile
        val lines = lock.readLines()
        val idx = lines.indexOfFirst { it.trim() == "name = \"rustls-platform-verifier-android\"" }
        check(idx >= 0) { "rustls-platform-verifier-android not found in $lock" }
        val version = lines.drop(idx + 1)
            .firstOrNull { it.trimStart().startsWith("version = ") }
            ?.substringAfter('"', "")?.substringBefore('"', "")
        check(!version.isNullOrEmpty()) { "version not found next to rustls-platform-verifier-android" }
        return version
    }
}

val rustlsVerifierVersion: Provider<String> =
    providers.of(RustlsVerifierVersion::class.java) {
        parameters.lockFile.set(coreDir.file("Cargo.lock"))
    }

configurations.configureEach {
    resolutionStrategy.eachDependency {
        if (requested.group == "org.rustls" && requested.name == "rustls-platform-verifier") {
            useVersion(rustlsVerifierVersion.get())
            because("the Kotlin component must match the rustls-platform-verifier-android crate version")
        }
    }
}

dependencies {
    val coroutinesVersion = "1.11.0"
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:$coroutinesVersion")
    implementation("androidx.annotation:annotation:1.9.1")
    // UI (docs/DESIGN.md §2: Jetpack Compose + Material 3). No navigation library: the app has
    // four tabs and two sub-pages, so a small state-based back stack is cheaper than the dependency.
    implementation(platform("androidx.compose:compose-bom:2026.06.01"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core:1.7.8")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.10.0")
    // Kotlin component of rustls-platform-verifier; version resolved from Cargo.lock above.
    implementation("org.rustls:rustls-platform-verifier")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:$coroutinesVersion")
    // The Android `org.json` stubs throw in local unit tests; this supplies a real implementation
    // so the config/stats JSON contract can be tested on the JVM without a device.
    testImplementation("org.json:json:20260814")
}
