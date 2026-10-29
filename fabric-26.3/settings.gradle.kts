// Copyright (c) 2026 AutoMint. License: see LICENSE.
pluginManagement { repositories { mavenCentral(); maven("https://maven.fabricmc.net"); gradlePluginPortal() } }
rootProject.name = "mintauth-fabric-26.3"
System.setProperty("mintauth.buildTarget", "fabric263")
includeBuild("..") { dependencySubstitution { substitute(module("online.automint:mintauth-core")).using(project(":core")) } }
