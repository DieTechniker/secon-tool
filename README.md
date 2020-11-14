# SECON Verschlüsselung auf Basis von [Crytographic Message Syntax](https://tools.ietf.org/html/rfc5652)

Diese Bibliothek implementiert einen sicheren Datenaustausch für die Kommunikation im Gesundheits- und Sozialwesen. Grundlage ist dabei die Spezifikation
der [GKV Anlage 16 SecuritySchnittstelle SECON](https://www.gkv-datenaustausch.de/media/dokumente/standards_und_normen/technische_spezifikationen/Anlage_16.pdf)
	
## Eingesetzte Technologien

+ [Cryptographic Message Syntax (CMS)](https://tools.ietf.org/html/rfc5652)
+ [BouncyCastle](https://bouncycastle.org/)
+ [Fun I/O](https://christian-schlichtherle.github.io/fun-io/)

## Übersicht

### Download

Aktuelle Version: https://search.maven.org/artifact/de.tk.opensource/secon-tool

Maven:

    <dependency>
      <groupId>de.tk.opensource</groupId>
      <artifactId>secon-tool</artifactId>
      <version>1.0.2</version>
    </dependency>

Gradle:

    implementation 'de.tk.opensource:secon-tool:1.0.2'

### Build

Um den Quellcode zu bauen sind folgende Schritte nötig

```shell script
git clone https://github.com/DieTechniker/secon-tool.git
cd secon-tool
./gradlew build
```

### Kommandozeilentool

Zum Signieren und Verschlüsseln einer Datei:

    java -jar build/libs/secon-tool-*-all.jar \
         -recipient <identifier> \
         -source <plainfile> -sink <cipherfile> \
         -keystore <storefile> -storepass <password> [-storetype <type>] \
         -alias <name> [-keypass <password>] \
        [-ldap <url>]

Zum Entschlüsseln und Verifizieren der Signatur einer Datei:

    java -jar build/libs/secon-tool-*-all.jar \
         -source <cipherfile> -sink <plainfile> \
         -keystore <storefile> -storepass <password> [-storetype <type>] \
         -alias <name> [-keypass <password>] \
        [-ldap <url>]

Für Hilfe zu der Bedeutung der einzelnen Parameter rufen Sie bitte das Tool ohne Parameter auf:

    java -jar build/libs/secon-tool-*-all.jar

#### Beispiel

Gemeinsamen Keystore für Alice und Bob einrichten:

```shell script
keytool -keystore keystore.p12 -storetype PKCS12 -storepass secret -genkey -alias alice -dname CN=alice -keyalg rsa -keysize 4096 -sigalg rsassa-pss -v
keytool -keystore keystore.p12 -storetype PKCS12 -storepass secret -genkey -alias bob   -dname CN=bob   -keyalg rsa -keysize 4096 -sigalg rsassa-pss -v
```

In diesem Beispiel teilen sich Alice und Bob der Einfachheit halber den Keystore mit den privaten Schlüsseln.
Im produktiven Einsatz hat natürlich jede Partei nur Zugriff auf Ihren eigenen privaten Schlüssel und die öffentlichen
Schlüssel der Kommunikationspartner sollten in Zertifikaten in einem LDAP-Server zur Verfügung gestellt werden.

Alice signiert und verschlüsselt nun einen Brief an Bob:

```shell script
echo 'Hello Bob!' > letter-to-bob.txt
java -jar build/libs/secon-tool-*-all.jar -keystore keystore.p12 -storepass secret -alias alice -recipient bob -source letter-to-bob.txt -sink letter-to-bob.cms
```

Schließlich entschlüsselt und verifiziert Bob den Brief von Alice:

```shell script
java -jar build/libs/secon-tool-*-all.jar -keystore keystore.p12 -storepass secret -alias bob -source letter-to-bob.cms -sink letter-from-alice.txt
cat letter-from-alice.txt
```

## API

Siehe [Sourcecode](src/main/java/de/tk/opensourcey/secon/SECON.java) und Javadoc der `SECON`-Klasse.
