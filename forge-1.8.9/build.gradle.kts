// Copyright (c) 2026 AutoMint. License: see LICENSE.
plugins {
    id("gg.essential.loom") version "1.15.51"
    id("dev.architectury.architectury-pack200") version "0.1.3"
    id("com.gradleup.shadow") version "9.2.2"
}
group = "online.automint"
version = "1.0.0"
base { archivesName.set("mintauth-forge-1.8.9") }
repositories { mavenCentral(); maven("https://maven.minecraftforge.net") }
val bundled by configurations.creating
configurations.implementation.get().extendsFrom(bundled)
dependencies {
    minecraft("com.mojang:minecraft:1.8.9")
    mappings("de.oceanlabs.mcp:mcp_stable:22-1.8.9")
    add("forge", "net.minecraftforge:forge:1.8.9-11.15.1.2318-1.8.9")
    bundled("online.automint:mintauth-core:1.0.0")
}
loom { forge { pack200Provider.set(dev.architectury.pack200.java.Pack200Adapter()) } }
java { toolchain { languageVersion.set(JavaLanguageVersion.of(8)) } }
tasks.processResources { from("../branding") { include("mint-logo.png", "mintauth-signature.png", "mintauth-signature.png.mcmeta"); into("assets/mintauth/textures/gui") }; inputs.property("version",project.version); filesMatching("mcmod.info") { expand("version" to project.version) } }
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

    configurations = listOf(bundled)
    archiveClassifier.set("bundled")
    relocate("com.google.gson","online.automint.mintauth.internal.gson")
    relocate("org.bouncycastle","online.automint.mintauth.internal.bc")
    exclude("META-INF/*.SF","META-INF/*.RSA","META-INF/*.DSA","module-info.class","META-INF/versions/**/module-info.class")
    exclude("META-INF/versions/**")
}
tasks.remapJar { dependsOn(tasks.shadowJar); inputFile.set(tasks.shadowJar.flatMap { it.archiveFile }); archiveClassifier.set("") }
tasks.withType<JavaCompile>().configureEach { options.encoding="UTF-8" }
tasks.withType<Jar>().configureEach { isPreserveFileTimestamps=false; isReproducibleFileOrder=true }

tasks.withType<JavaExec>().configureEach {
    if (name == "runClient") {
        javaLauncher.set(javaToolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(8)) })
        providers.gradleProperty("mintauthSmokeRoot").orNull?.let {
            jvmArgs("-Dmintauth.testVaultRoot=$it", "-Dmintauth.smoke=true")
        }
    }
}
