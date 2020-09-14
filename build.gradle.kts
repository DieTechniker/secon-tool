/*
 * Copyright © 2020 Techniker Krankenkasse
 * Copyright © 2020 BITMARCK Service GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
group = "de.tk.security"
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

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            pom {
                name.set("kks-encryption")
                description.set("A library for secure communication in german health care and social affairs sector. Based on specifications in 'GKV Anlage 16 SECON'")
                url.set("https://github.com/DieTechniker/kks-encryption")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
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