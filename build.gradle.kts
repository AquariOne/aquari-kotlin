buildscript {
    dependencies {
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.3.21")
    }
}

plugins {
    kotlin("jvm") version "2.3.21" apply false
    kotlin("plugin.serialization") version "2.3.21" apply false
    id("com.android.library") version "9.4.0" apply false
    `maven-publish`
}

allprojects {
    group = "one.aquari"
    version = "1.0.0"
}
