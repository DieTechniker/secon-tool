# SECON Verschlüsselung auf Basis von [Crytographic Message Syntax](https://tools.ietf.org/html/rfc5652)

Dieses Repository stellt eine Bibliothek und ein Kommandozeilentool zum sicheren Datenaustausch für die Kommunikation im
Gesundheits- und Sozialwesen bereit.
Grundlage ist die Spezifikation vom GKV-SV in der [Anlage - 16 Security Schnittstelle (SECON)].
	
## Eingesetzte Technologien

+ [Cryptographic Message Syntax (CMS)](https://tools.ietf.org/html/rfc5652)
+ [BouncyCastle](https://bouncycastle.org/)
+ [Fun I/O](https://christian-schlichtherle.github.io/fun-io/)

## Übersicht

### Download

Aktuelle Version: https://search.maven.org/artifact/de.tk.opensource/secon-tool

Maven:

```xml
<dependency>
    <groupId>de.tk.opensource</groupId>
    <artifactId>secon-tool</artifactId>
    <version>1.2.0</version>
</dependency>
```

Gradle:

```kotlin
implementation 'de.tk.opensource:secon-tool:1.2.0'
```

### Build

Um den Quellcode zu bauen sind folgende Schritte nötig

```shell script
git clone https://github.com/DieTechniker/secon-tool.git
cd secon-tool
./gradlew build
```

### Kommandozeilentool

Das Kommandozeilentool lässt sich am einfachsten mittels der JAR-Assembly-Datei `secon-tool-*-all.jar` aufrufen.
Für Inline-Hilfe zu den einzelnen Parametern rufen Sie bitte das Tool ohne irgendwelche Parameter auf:

```shell script
$ java -jar build/libs/secon-tool-*-all.jar
Error: -storepass parameter is undefined.

Usage:

To sign and encrypt:

    java -jar build/libs/secon-tool-*-all.jar \
        -recipient <identifier> \
        -source <plainfile> -sink <cipherfile> \
        -keystore <storefile> -storepass <password> [-storetype <type>] \
        -alias <name> [-keypass <password>] \
       [-ldap <url>]

To decrypt and verify:

    java -jar build/libs/secon-tool-*-all.jar \
        -source <cipherfile> -sink <plainfile> \
        -keystore <storefile> -storepass <password> [-storetype <type>] \
        -alias <name> [-keypass <password>] \
       [-ldap <url>]

Parameters:

    -alias <name>
        The alias name of the private key entry in the Java key store which is used to prove your identity.

    -keypass <password>
        The password for the private key entry in the Java key store.
        If not provided then it defaults to the password for the Java key store.

    -keystore <path>
        The pathname of a file for the Java key store.

    -ldap <url>
        The URL of an LDAP server holding the certificate of the communication partner.
        The LDAP server must allow anonymous access and the schema of its Directory Information Tree must conform to
        chapter 4.6.2  "LDAP-Verzeichnis" der "Security-Schnittstelle (SECON) - Anlage 16", see
        https://www.gkv-datenaustausch.de/media/dokumente/standards_und_normen/technische_spezifikationen/Anlage_16_-_Security-Schnittstelle.pdf .
        If not provided then the certificate is only looked up in the Java key store.

    -recipient <identifier>
        The identifier of the message recipient. This is can be an alias in the Java key store or an
        "Institutionskennzeichen" in the LDAP server, if configured.

    -sink <path>
    -source <path>
        The pathname of a file for the plaintext or the ciphertext.

    -storepass <password>
        The password for the Java key store.

    -storetype <type>
        The type of the Java key store, see
        https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyStore .
        If not provided then it defaults to PKCS12.
```

#### Beispiel

Im folgenden Beispiel teilen sich Alice und Bob der Einfachheit halber denselben Keystore mit ihren privaten Schlüsseln:

```shell script
keytool -keystore keystore.p12 -storetype PKCS12 -storepass secret -genkey -alias alice -dname CN=alice -keyalg rsa -keysize 4096 -sigalg rsassa-pss -v
keytool -keystore keystore.p12 -storetype PKCS12 -storepass secret -genkey -alias bob   -dname CN=bob   -keyalg rsa -keysize 4096 -sigalg rsassa-pss -v
```

Im produktiven Einsatz darf jede Partei natürlich nur Zugriff auf ihren eigenen privaten Schlüssel haben.
Entsprechend muss sich jede Partei einen eigenen Keystore mit ihrem privaten Schlüssel anlegen und für die öffentlichen
Schlüssel der Kommunikationspartner sollte ein LDAP-Server mit Zertifikaten zur Verfügung gestellt werden.
Das Schema des Directory Information Tree muss Kapitel 4.6.2 "LDAP-Verzeichnis" der
[Anlage - 16 Security Schnittstelle (SECON)] entsprechen.
Der URL des LDAP-Servers kann im Kommandozeilentool über den Parameter `-ldap <url>` angegeben werden. 

Als nächstes signiert und verschlüsselt Alice einen Brief an Bob:

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

[API-Tutorial](https://github.com/DieTechniker/secon-tool/wiki/Getting-started) mit Code-Beispielen im Wiki

Siehe [Sourcecode](src/main/java/de/tk/opensource/secon/SECON.java) und Javadoc der `SECON`-Klasse.

[Anlage - 16 Security Schnittstelle (SECON)]: https://www.gkv-datenaustausch.de/media/dokumente/standards_und_normen/technische_spezifikationen/Anlage_16_-_Security_Schnittstelle.pdf
