# SECON Verschlüsselung auf Basis von [Crytographic Message Syntax](https://tools.ietf.org/html/rfc5652)

Diese Bibliothek implementiert einen sicheren Datenaustausch für die Kommunikation im Gesundheits- und Sozialwesen. Grundlage ist dabei die Spezifikation
der [GKV Anlage 16 SecuritySchnittstelle SECON](https://www.gkv-datenaustausch.de/media/dokumente/standards_und_normen/technische_spezifikationen/Anlage_16.pdf)
	
## Eingesetzte Technologien

[Cryptographic Message Syntax (CMS)](https://tools.ietf.org/html/rfc5652) 

[BouncyCastle](https://bouncycastle.org/)

[Fun I/O](https://christian-schlichtherle.github.io/fun-io/)

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

```
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

## API

Siehe [Sourcecode](src/main/java/de/tk/opensourcey/secon/SECON.java) und Javadoc der `SECON`-Klasse.
