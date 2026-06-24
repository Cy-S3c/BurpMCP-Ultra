plugins {
    kotlin("jvm") version "2.1.20"
    kotlin("plugin.serialization") version "2.1.20"
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "com.v0rt3x.burpmcp"
version = "2.1.0"

// Pin the build to a JDK 17 toolchain on every OS (Windows / macOS / Linux).
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
