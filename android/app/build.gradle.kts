plugins {
    id("com.android.application")
}

android {
    namespace = "org.suika.suikaauthenticator"
    compileSdk = 36
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "org.suika.suikaauthenticator"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"

        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
}

dependencies {
    implementation("androidx.biometric:biometric:1.1.0")

    // CameraX owns lifecycle-aware camera preview and image analysis.
    implementation("androidx.camera:camera-camera2:1.7.0")
    implementation("androidx.camera:camera-lifecycle:1.7.0")
    implementation("androidx.camera:camera-view:1.7.0")

    // Bundle the QR model so scanning is immediately available without a runtime download.
    implementation("com.google.mlkit:barcode-scanning:17.3.0")
}
