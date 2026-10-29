// Copyright (c) 2026 AutoMint. License: see LICENSE.
pluginManagement { repositories { mavenCentral(); maven("https://maven.fabricmc.net"); gradlePluginPortal() } }
rootProject.name = "mintauth-fabric-1.21.11"
System.setProperty("mintauth.buildTarget", "fabric121")
includeBuild("..") { dependencySubstitution { substitute(module("online.automint:mintauth-core")).using(project(":core")) } }
