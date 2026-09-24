import java.io.FileInputStream
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

val supportedAbis = listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
val targetAbis = providers.gradleProperty("androidAbis")
    .map { it.split(',').map(String::trim).distinct() }
    .getOrElse(supportedAbis)
require(targetAbis.isNotEmpty() && targetAbis.all { it in supportedAbis }) {
    "androidAbis must be a comma-separated selection of: ${supportedAbis.joinToString()}"
}
val nativeOutput = layout.buildDirectory.dir("generated/arpcut/jniLibs")
val buildArpcut by tasks.registering(Exec::class) {
    inputs.files(rootProject.fileTree("native/arpcut") {
        include("*.go", "go.mod", "go.sum", "build.sh")
    })
    inputs.property("abis", targetAbis)
    outputs.dir(nativeOutput)
    environment("ARPCUT_OUTPUT_DIR", nativeOutput.get().asFile.absolutePath)
    commandLine(listOf("sh", rootProject.file("native/arpcut/build.sh").absolutePath) + targetAbis)
}
tasks.named("preBuild") { dependsOn(buildArpcut) }

// Release signing credentials live in keystore.properties at the project base.
val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties().apply {
    if (keystorePropertiesFile.exists()) load(FileInputStream(keystorePropertiesFile))
}

android {
    namespace = "com.bettercut"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.bettercut"
        minSdk = 24
        targetSdk = 36
        versionCode = providers.gradleProperty("releaseVersionCode").orElse("1").get().toInt()
        versionName = providers.gradleProperty("releaseVersionName").orElse("1.0").get()

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            abiFilters += targetAbis
        }
    }

    sourceSets.getByName("main").jniLibs.setSrcDirs(listOf(nativeOutput))

    // Ship the arpcut executable as libarpcut.so and force it to be
    // extracted to the app's nativeLibraryDir, which is the only app-owned
    // location that is not mounted noexec on modern Android.
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    signingConfigs {
        create("release") {
            val signingFile = providers.environmentVariable("ANDROID_KEYSTORE_FILE").orNull
            if (signingFile != null) {
                storeFile = file(signingFile)
                storePassword = providers.environmentVariable("ANDROID_KEYSTORE_PASSWORD").get()
                keyAlias = providers.environmentVariable("ANDROID_KEY_ALIAS").get()
                keyPassword = providers.environmentVariable("ANDROID_KEY_PASSWORD").get()
            } else if (keystorePropertiesFile.exists()) {
                storeFile = rootProject.file(keystoreProperties["storeFile"] as String)
                storePassword = keystoreProperties["storePassword"] as String
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["keyPassword"] as String
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("release")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
    buildFeatures {
        compose = true
    }
}

dependencies {

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.material.icons.extended)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.ui.test.junit4)
    debugImplementation(libs.androidx.ui.tooling)
    debugImplementation(libs.androidx.ui.test.manifest)
}
