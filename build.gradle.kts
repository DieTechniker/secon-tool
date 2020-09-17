/*
 * Copyright © 2020 Techniker Krankenkasse
 * Copyright © 2020 BITMARCK Service GmbH
 *
 * This file is part of kks-encryption
 * (see https://github.com/DieTechniker/kks-encryption).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
group = "de.tk.opensource"
version = "0.0.1-SNAPSHOT"

application {
    mainClassName = "de.tk.security.kks.Main"
}

dependencies {
    val junitVersion = "5.6.2"

    implementation("global.namespace.fun-io:fun-io-bios:2.4.0")
    implementation("org.bouncycastle:bcpkix-jdk15on:1.66")

    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitVersion")
}

plugins {
    application
    `java-library`
    `maven-publish`
    id("com.github.johnrengelman.shadow") version "6.0.0"
	id("net.minecrell.licenser") version "0.4.1"
}

repositories {
    mavenCentral()
}

java {
    withJavadocJar()
    withSourcesJar()
}

val encoding = "UTF-8"

tasks.compileJava {
    options.encoding = encoding
    options.release.set(8)
}

tasks.javadoc {
    options.encoding = encoding
}

tasks.jar {
    manifest {
        attributes(
                "Sealed" to true
        )
    }
}

tasks.compileTestJava {
    options.encoding = encoding
    options.release.set(8)
}

tasks.test {
    useJUnitPlatform {
        excludeTags("LDAP")
    }
}

tasks.register<Test>("testLdap") {
    useJUnitPlatform {
        includeTags("LDAP")
    }
}

license {
	header = project.file("LICENSE.header")
	include("**/*.java,**/*.kts")
	newLine = false
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            pom {
                name.set("kks-encryption")
                description.set("A library for secure communication in german health care and social affairs sector. Based on specifications in 'GKV Anlage 16 SECON'")
                url.set("https://github.com/DieTechniker/kks-encryption")
                licenses {
                    license {
                        name.set("GNU Lesser General Public License, Version 3")
                        url.set("https://www.gnu.org/licenses/lgpl-3.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("loetifuss")
                        name.set("Wolfgang Schmiesing")
                        email.set("wolfgang.schmiesing@googlemail.com")
                    }
                }
                scm {
                    connection.set("scm:git:git://example.com/my-library.git")
                    developerConnection.set("scm:git:ssh://example.com/my-library.git")
                    url.set("https://github.com/DieTechniker/kks-encryption")
                }
            }
        }
    }
	
	repositories {
        maven {
            val releasesRepoUrl = "$buildDir/repos/releases"
            val snapshotsRepoUrl = "$buildDir/repos/snapshots"
            url = uri(if (version.toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl)
        }
    }
	
    repositories {
        maven {		
            // MavenCentral
			name = "OSSRH"
            val releasesRepoUrl = "https://oss.sonatype.org/service/local/staging/deploy/maven2/"
            val snapshotsRepoUrl = "https://oss.sonatype.org/content/repositories/snapshots"
            url = uri(if (version.toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl)
            credentials {
                username = System.getenv("MAVEN_USERNAME")
                password = System.getenv("MAVEN_PASSWORD")				
            }			
        }
        maven {
            // GitHubPackages
			name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/DieTechniker/kks-encryption")
            credentials {
                username = System.getenv("GITHUB_ACTOR")
                password = System.getenv("GITHUB_TOKEN")
            }			
        }		
    }
}