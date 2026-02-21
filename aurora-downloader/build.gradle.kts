import org.gradle.api.tasks.Copy

plugins {
    kotlin("jvm") version "2.3.10"
    kotlin("plugin.serialization") version "2.3.10"
    application
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

kotlin {
    jvmToolchain(21)
}

repositories {
    mavenCentral()
}

val gplayapiVersion = "3.5.6"

dependencies {
    implementation("com.squareup.okhttp3:okhttp:5.3.2")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.10.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    implementation("com.google.android:android:4.1.1.4")
    implementation("com.google.protobuf:protobuf-javalite:4.31.0")
    implementation("com.google.code.gson:gson:2.13.1")
}

val gplayapiAar by configurations.creating

dependencies {
    gplayapiAar("com.auroraoss:gplayapi:$gplayapiVersion@aar")
}

val extractGplayapiJar by tasks.registering(Copy::class) {
    from({
        zipTree(gplayapiAar.singleFile).matching { include("classes.jar") }
    })
    into(layout.buildDirectory.dir("gplayapi"))
    rename("classes.jar", "gplayapi-classes.jar")
}

val gplayapiClassesJar = layout.buildDirectory.file("gplayapi/gplayapi-classes.jar")
val gplayapiClasses = files(gplayapiClassesJar).builtBy(extractGplayapiJar)

dependencies {
    implementation(gplayapiClasses)
}

tasks.matching { it.name in setOf("compileKotlin", "compileJava") }.configureEach {
    dependsOn(extractGplayapiJar)
}

application {
    mainClass.set("com.droidhunter.aurora.MainKt")
}
