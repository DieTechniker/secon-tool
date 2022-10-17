/*
 * Copyright © 2020 Techniker Krankenkasse
 * Copyright © 2020 BITMARCK Service GmbH
 *
 * This file is part of secon-tool
 * (see https://github.com/DieTechniker/secon-tool).
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
version = "1.2.0-SNAPSHOT"

application {
    mainClassName = "de.tk.opensource.secon.Main"
}

dependencies {
    val junitVersion = "5.6.2"

    implementation("global.namespace.fun-io:fun-io-bios:2.4.0")
    implementation("org.bouncycastle:bcpkix-jdk15on:1.70")

    testImplementation(platform("io.projectreactor:reactor-bom:2020.0.2"))
    testImplementation("io.projectreactor:reactor-test")
    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitVersion")
}

plugins {
    application
    `java-library`
    `maven-publish`
    signing
    id("com.github.johnrengelman.shadow") version "7.1.2"
    id("biz.aQute.bnd.builder") version "6.1.0"
    id("org.cadixdev.licenser") version "0.6.1"
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
	header(project.file("LICENSE.header"))
	include("**/*.java,**/*.kts")
	newLine.set(false)
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
			from(components["java"])
            pom {
                name.set("secon-tool")
                description.set("A library for secure communication in the German health care and social affairs sector. Based on specifications in 'GKV Anlage 16 SECON'")
                url.set("https://github.com/DieTechniker/secon-tool")
                licenses {
                    license {
                        name.set("GNU Lesser General Public License, Version 3")
                        url.set("https://www.gnu.org/licenses/lgpl-3.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("christian-schlichtherle")
                        name.set("Christian Schlichtherle")
                        email.set("christian@schlichtherle.de")
                    }			
                    developer {
                        id.set("loetifuss")
                        name.set("Wolfgang Schmiesing")
                        email.set("wolfgang.schmiesing@googlemail.com")
                    }
                }
                scm {
                    connection.set("scm:git:git://github.com/DieTechniker/secon-tool.git")
                    developerConnection.set("scm:git:ssh://github.com/DieTechniker/secon-tool.git")
                    url.set("https://github.com/DieTechniker/secon-tool")
                }
            }
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
/*
        maven {
            // GitHubPackages
			name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/DieTechniker/secon-tool")
            credentials {
                username = System.getenv("GITHUB_ACTOR")
                password = System.getenv("GITHUB_TOKEN")
            }			
        }		
*/	
    }
}

signing {
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKey, signingPassword)
    sign(publishing.publications["mavenJava"])	
}
