# KKS Verschlüsselung auf Basis von [Crytographic Message Syntax](https://tools.ietf.org/html/rfc5652)

Diese Bibliothek implementiert einen sicheren Datenaustausch für die Kommunikation im Gesundheits- und Sozialwesen. Grundlage ist dabei die Spezifikation
der [GKV Anlage 16 SecuritySchnittstelle SECON](https://www.gkv-datenaustausch.de/media/dokumente/standards_und_normen/technische_spezifikationen/Anlage_16_-_Security-Schnittstelle.pdf)
	
## Eingesetzte Technologien

[Cryptographic Message Syntax (CMS)](https://tools.ietf.org/html/rfc5652) 

[BouncyCastle](https://bouncycastle.org/)

[Fun I/O](https://christian-schlichtherle.github.io/fun-io/)

## Getting started

Aktuell gibt es noch kein offizielles Release auf Maven Central. Dies wird aber in Kürze erfolgen.
Daher muss der Quellcode aktuell zunächst gebaut werden.

```
git clone https://github.com/DieTechniker/kks-encryption.git
cd kks-encryption
./gradlew build
```

### Kommandozeilentool

Zum Signieren und Verschlüsseln einer Datei:

    java -jar build/libs/kks-*-all.jar -recipient <identifier> -source <plainfile> -sink <cipherfile> -keystore <storefile> -storepass <password> [-storetype <type>] -alias <name> [-keypass <password>] [-ldap <url>]

Zum Entschlüsseln und Verifizieren der Signatur einer Datei:

    java -jar build/libs/kks-*-all.jar -source <cipherfile> -sink <plainfile> -keystore <storefile> -storepass <password> [-storetype <type>] -alias <name> -keypass <password> [-ldap <url>]

## API

Siehe [Sourcecode](src/main/java/de/tk/security/kks/KKS.java) und Javadoc der `KKS`-Klasse.
