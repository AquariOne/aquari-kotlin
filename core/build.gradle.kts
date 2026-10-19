import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    `java-library`
    `maven-publish`
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
    withSourcesJar()
    withJavadocJar()
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        allWarningsAsErrors.set(true)
        freeCompilerArgs.add("-Xjsr305=strict")
    }
}

dependencies {
    api("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
    api("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
    implementation("com.squareup.okhttp3:okhttp:5.5.0")
    implementation("com.nimbusds:nimbus-jose-jwt:10.10")

    testImplementation(kotlin("test-junit5"))
}

tasks.test {
    useJUnitPlatform()
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "aquari-core"
            from(components["java"])
            pom {
                name.set("Aquari One Kotlin Core SDK")
                description.set("Official Aquari One Kotlin OAuth and Passport client SDK")
                url.set("https://docs.aquari.one/sdks/kotlin")
                licenses {
                    license {
                        name.set("Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                        distribution.set("repo")
                    }
                }
                organization {
                    name.set("Aquari One LLC")
                    url.set("https://aquari.one")
                }
                scm {
                    url.set("https://gitlab.com/nousen-group/aquari/aquari-kotlin")
                    connection.set("scm:git:https://gitlab.com/nousen-group/aquari/aquari-kotlin.git")
                    developerConnection.set("scm:git:https://gitlab.com/nousen-group/aquari/aquari-kotlin.git")
                }
                developers {
                    developer {
                        id.set("aquari-one")
                        name.set("Aquari One")
                    }
                }
            }
        }
    }
    repositories {
        maven {
            name = "localArtifacts"
            // Standalone SDK repo defaults to its own artifact directory.
            // Private monorepo acceptance may override this Gradle property.
            url = uri(providers.gradleProperty("aquariLocalArtifactsPath")
                .getOrElse(rootProject.layout.projectDirectory.dir("build/localArtifacts/m2").asFile.absolutePath))
        }
    }
}
