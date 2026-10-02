plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.persona.mobile"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.persona.mobile"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        // jniLibs 只由 CI 注入 arm64 的 libpersona_mobile.so（desktop-build.yml
        // android job：cargo ndk 产出后拷入 src/main/jniLibs/arm64-v8a），
        // 限定单 ABI 防非 arm64 设备运行时 UnsatisfiedLinkError
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            // nightly/分发产物用 debug keystore 签名：免 CI 秘钥管理，产物名
            // 固定 app-release.apk（unsigned 会变 app-release-unsigned.apk，
            // 下游 release job 的改名步骤按名取件会扑空）；正式商店包另立签名
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
}
