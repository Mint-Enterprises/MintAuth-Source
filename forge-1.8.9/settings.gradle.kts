// Copyright (c) 2026 AutoMint. License: see LICENSE.
pluginManagement { repositories { mavenCentral(); maven("https://maven.fabricmc.net"); maven("https://maven.minecraftforge.net"); maven("https://repo.essential.gg/repository/maven-public"); maven("https://maven.architectury.dev"); gradlePluginPortal() } }
rootProject.name = "mintauth-forge-1.8.9"
System.setProperty("mintauth.buildTarget", "forge189")
includeBuild("..") { dependencySubstitution { substitute(module("online.automint:mintauth-core")).using(project(":core")) } }
