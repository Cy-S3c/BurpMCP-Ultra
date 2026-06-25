plugins {
    kotlin("jvm") version "2.1.20"
    kotlin("plugin.serialization") version "2.1.20"
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "com.v0rt3x.burpmcp"
version = "2.1.1"

// Build-JDK (GitHub issue #2): Kotlin 2.1.20 cannot even COMPILE the Gradle .kts
// scripts under Java 22+ (cryptic "25.0.3" crash), so a script-level version
// guard is impossible. gradle/gradle-daemon-jvm.properties pins the Gradle daemon
// to a JDK 17 toolchain, so `./gradlew` auto-runs the build under JDK 17 even
// when launched with Burp's bundled Java 25 (requires a JDK 17 installed/discoverable).

// Pin compilation to a JDK 17 toolchain on every OS (Windows / macOS / Linux).
// Gradle auto-detects an installed JDK 17 and uses it to compile, regardless of
// which JVM launched Gradle. This guarantees the fat JAR is always Java 17
// bytecode and fixes the "built with Burp's bundled Java 25 -> MCP SSE ports
// 9876/9877 silently fail to bind" problem (GitHub issue #2). If no JDK 17 is
// found, Gradle fails with a clear, actionable error instead of silently
// producing a broken artifact.
kotlin {
    jvmToolchain(17)
}

repositories {
    mavenCentral()
}

val ktorVersion = "3.2.3"

dependencies {
    // Burp Suite Montoya API — provided by Burp at runtime, not bundled in the fat JAR
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.2")

    // MCP Kotlin SDK (server component) — requires Ktor 3.2.3
    implementation("io.modelcontextprotocol:kotlin-sdk-server:0.8.3")

    // Kotlin coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")

    // Kotlin serialization
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.1")

    // Ktor server — versions must match what kotlin-sdk-server 0.8.3 was compiled against
    implementation("io.ktor:ktor-server-cio:$ktorVersion")
    implementation("io.ktor:ktor-server-sse:$ktorVersion")
    implementation("io.ktor:ktor-server-cors:$ktorVersion")
    implementation("io.ktor:ktor-server-content-negotiation:$ktorVersion")
    implementation("io.ktor:ktor-serialization-kotlinx-json:$ktorVersion")

    // Testing — JUnit 5 via kotlin-test
    testImplementation(kotlin("test-junit5"))
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}

tasks.compileKotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

tasks.compileTestKotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

// --- Single-sourced version -------------------------------------------------
// Generate BuildInfo.VERSION from the Gradle project `version` so every runtime
// reference (UI tab, dashboard, MCP server identity) stays in lockstep with
// build.gradle.kts and can never drift again (e.g. the old hardcoded dashboard
// "v2.0" label). Bumping `version` above is now the ONLY edit needed.
val generatedVersionDir = layout.buildDirectory.dir("generated/version/kotlin")
val generateBuildInfo by tasks.registering {
    val outDir = generatedVersionDir
    val ver = project.version.toString()
    inputs.property("version", ver)
    outputs.dir(outDir)
    doLast {
        val f = outDir.get().file("com/burpmcp/ultra/core/BuildInfo.kt").asFile
        f.parentFile.mkdirs()
        f.writeText(
            """
            |package com.burpmcp.ultra.core
            |
            |/** Generated from the Gradle project version — do not edit by hand. */
            |object BuildInfo {
            |    const val VERSION: String = "$ver"
            |}
            |""".trimMargin()
        )
    }
}
kotlin.sourceSets["main"].kotlin.srcDir(generatedVersionDir)
tasks.named("compileKotlin") { dependsOn(generateBuildInfo) }

tasks.shadowJar {
    archiveBaseName.set("burpmcp-ultra")
    archiveClassifier.set("")

    // Merge META-INF/services files — critical for ServiceLoader-based discovery
    // (Ktor engines, kotlinx-serialization formats, etc.)
    mergeServiceFiles()

    // Exclude the Montoya API from the fat JAR; Burp Suite provides it at runtime
    dependencies {
        exclude(dependency("net.portswigger.burp.extensions:montoya-api"))
    }
}

// Make 'build' depend on shadowJar so a fat JAR is always produced
tasks.build {
    dependsOn(tasks.shadowJar)
}

// Convenience task: copy the built fat JAR to the project root for easy loading into Burp
tasks.register<Copy>("copyJar") {
    dependsOn(tasks.shadowJar)
    from(tasks.shadowJar.get().archiveFile)
    into(layout.projectDirectory)
    rename { "burpmcp-ultra.jar" }
}
