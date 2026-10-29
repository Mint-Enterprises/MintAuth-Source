// Copyright (c) 2026 AutoMint. License: see LICENSE.
plugins { `java-library` }
val target = System.getProperty("mintauth.buildTarget", "core")
require(target in setOf("core", "forge189", "fabric121", "fabric263"))
layout.buildDirectory.set(rootProject.layout.projectDirectory.dir(".tools/builds/$target/core"))
java { toolchain { languageVersion.set(JavaLanguageVersion.of(8)) }; withSourcesJar() }
dependencies {
    api("com.google.code.gson:gson:2.13.2")
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
    implementation("net.java.dev.jna:jna:5.18.1")
    implementation("net.java.dev.jna:jna-platform:5.18.1")
    testImplementation("junit:junit:4.13.2")
}
tasks.withType<JavaCompile>().configureEach { options.encoding = "UTF-8" }
val sourceCommit = providers.exec { workingDir(rootProject.projectDir); commandLine("git", "rev-parse", "HEAD") }.standardOutput.asText.map { it.trim() }
val sourceTime = providers.exec { workingDir(rootProject.projectDir); commandLine("git", "show", "-s", "--format=%ct", "HEAD") }.standardOutput.asText.map { it.trim() }
val generateBuildInfo = tasks.register("generateBuildInfo") {
    inputs.property("sourceCommit", sourceCommit); inputs.property("sourceTime", sourceTime)
    inputs.property("version", rootProject.version.toString())
    val output = layout.buildDirectory.dir("generated/mintauth-build")
    outputs.dir(output)
    doLast {
        require(sourceCommit.get().matches(Regex("[a-f0-9]{40}")))
        require(sourceTime.get().matches(Regex("[0-9]{1,13}")))
        val file = output.get().file("META-INF/mintauth/build.json").asFile
        file.parentFile.mkdirs()
        val version = rootProject.version.toString()
        require(version.matches(Regex("[A-Za-z0-9.+_-]{1,64}")))
        file.writeText("{\"version\":\"" + version + "\",\"commit\":\"" + sourceCommit.get() + "\",\"committedAt\":" + sourceTime.get() + "}\n")
    }
}
tasks.processResources {
    dependsOn(generateBuildInfo)
    from(layout.buildDirectory.dir("generated/mintauth-build"))
    from(rootProject.file("signing/release-public.pub")) { into("META-INF/mintauth") }
    from(rootProject.file("signing/jar-signing.crt")) { into("META-INF/mintauth") }
    from(rootProject.file("LICENSE")) { into("META-INF/mintauth"); rename { "LICENSE.txt" } }
    from(rootProject.file("NOTICE")) { into("META-INF/mintauth"); rename { "THIRD_PARTY.md" } }
    from(rootProject.file("README.md")) { into("META-INF/mintauth"); rename { "SCANNER-NOTES.md" } }
}
tasks.withType<Jar>().configureEach { isPreserveFileTimestamps = false; isReproducibleFileOrder = true }
