// Copyright (c) 2026 AutoMint. License: see LICENSE.
plugins { id("net.fabricmc.fabric-loom") version "1.19.3"; id("com.gradleup.shadow") version "9.2.2" }
group="online.automint";version="1.0.0"
base { archivesName.set("mintauth-fabric-26.3") }
repositories { mavenCentral() }
val bundled by configurations.creating
configurations.implementation.get().extendsFrom(bundled)
dependencies {
    minecraft("com.mojang:minecraft:26.3")
    implementation("net.fabricmc:fabric-loader:0.20.1")
    implementation("net.fabricmc.fabric-api:fabric-api:0.165.0+26.3")
    bundled("online.automint:mintauth-core:1.0.0")
}
java { toolchain { languageVersion.set(JavaLanguageVersion.of(25)) } }
tasks.withType<JavaCompile>().configureEach { options.release.set(25);options.encoding="UTF-8" }
tasks.processResources { from("../branding") { include("mint-logo.png", "mintauth-signature.png", "mintauth-signature.png.mcmeta"); into("assets/mintauth/textures/gui") }; inputs.property("version",project.version);filesMatching("fabric.mod.json") { expand("version" to project.version) } }
tasks.shadowJar {
    minimize {
        exclude(dependency("com.google.code.gson:.*:.*"))
        exclude(dependency("net.java.dev.jna:.*:.*"))
    }
    exclude("META-INF/versions/**/org/bouncycastle/**")
    exclude("META-INF/services/java.security.Provider")
    val supportedNatives = setOf(
        "com/sun/jna/win32-x86-64/jnidispatch.dll",
        "com/sun/jna/linux-x86-64/libjnidispatch.so",
        "com/sun/jna/darwin-x86-64/libjnidispatch.jnilib",
        "com/sun/jna/darwin-aarch64/libjnidispatch.jnilib"
    )
    eachFile {
        if (path.startsWith("com/sun/jna/") && path.matches(Regex(".*\\.(dll|so|jnilib|a|dylib)$"))
            && path !in supportedNatives) exclude()
    }

    configurations=listOf(bundled);archiveClassifier.set("")
    relocate("com.google.gson","online.automint.mintauth.internal.gson")
    relocate("org.bouncycastle","online.automint.mintauth.internal.bc")
    exclude("META-INF/*.SF","META-INF/*.RSA","META-INF/*.DSA","module-info.class","META-INF/versions/**/module-info.class")
}
tasks.jar { archiveClassifier.set("thin") }
tasks.build { dependsOn(tasks.shadowJar) }
tasks.withType<Jar>().configureEach { isPreserveFileTimestamps=false;isReproducibleFileOrder=true }

tasks.withType<JavaExec>().configureEach {
    if (name == "runClient") {
        javaLauncher.set(javaToolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(25)) })
        providers.gradleProperty("mintauthSmokeRoot").orNull?.let {
            jvmArgs("-Dmintauth.testVaultRoot=$it", "-Dmintauth.smoke=true")
        }
    }
}
