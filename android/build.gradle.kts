plugins {
    id("com.android.library")
    `maven-publish`
}

android {
    namespace = "one.aquari.android"
    compileSdk = 37

    defaultConfig {
        minSdk = 26
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

dependencies {
    api(project(":core"))
    implementation("androidx.browser:browser:1.10.0")
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                artifactId = "aquari-android"
                from(components["release"])
                pom {
                    name.set("Aquari One Android SDK")
                    description.set("Official Aquari One Android OAuth browser and session adapter SDK")
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
}
