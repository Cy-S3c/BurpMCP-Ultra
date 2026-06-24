// Build-JDK is pinned to a JDK 17 toolchain via gradle/gradle-daemon-jvm.properties
// (a script-level guard is impossible — Kotlin 2.1.20 can't even COMPILE these
// .kts scripts under Java 22+, crashing with a cryptic "25.0.3"). The daemon
// criteria make `./gradlew` relaunch the build under JDK 17 even when launched
// with Burp's bundled Java 25. See GitHub issue #2.
rootProject.name = "burpmcp-ultra"
