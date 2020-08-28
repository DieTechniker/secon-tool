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
package de.tk.security.kks;

import global.namespace.fun.io.api.Socket;
import global.namespace.fun.io.api.Source;
import global.namespace.fun.io.bios.BIOS;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.naming.Context;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.security.KeyStore;
import java.security.Security;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.concurrent.Callable;

import static java.util.Objects.requireNonNull;

/**
 * Stellt CMS-Dienste (Cryptographic Message Syntax) für das Krankenkassenkommunikationssystem (KKS) bereit.
 * Diese Fassade ist der Haupteinstiegspunkt von diesem API.
 * <p>
 * Im folgenden Beispiel signiert Alice zunächst eine Nachricht mit ihrem privaten Schlüssel und verschlüsselt diese
 * dann mit dem öffentlichen Schlüssel aus dem Zertifikat für Bob.
 * Bob wiederum entschlüsselt die Nachricht mit seinem privaten Schlüssel und überprüft die Signatur von Alice mit dem
 * öffentlichen Schlüssel aus dem Zertifikat für Alice.
 * Die privaten Schlüsselpaare werden der Einfachheit halber in einem Schlüsselbund im PKCS12-Format gespeichert.
 * Für dieses Beispiel benötigt der Schlüsselbund daher lediglich zwei Einträge mit den privaten Schlüsselpaaren für
 * Alice und Bob.
 * <pre>{@code
 * import java.io.*;
 * import java.security.*;
 * import java.util.concurrent.Callable;
 *
 * import de.tk.security.kks.*;
 *
 * import static de.tk.security.kks.KKS.*;
 *
 * class Scratch {
 *
 *     public static void main(String... unused) throws KksException {
 *         // Wir benötigen einen Schlüsselbund mit jeweils einem eigenen privaten Schlüsselbund-Eintrag für Alice und
 *         // Bob:
 *         KeyStore keyStore = keyStore(() -> new FileInputStream("keystore.p12"), "secret"::toCharArray);
 *
 *         // Als nächstes erzeugen beide Kommunikationsteilnehmer jeweils eine eigene Identität:
 *         KksIdentity aliceId = identity(keyStore, "Alice's alias", "Alice's password"::toCharArray);
 *         KksIdentity bobId = identity(keyStore, "Bob's alias", "Bob's password"::toCharArray);
 *
 *         // Außerdem verwenden beide Kommunikationsteilnehmer denselben Schlüsselbund als Verzeichnisdienst für
 *         // Zertifikate:
 *         KksDirectory keyStoreDir = directory(keyStore);
 *
 *         // Beide Kommunikationsteilnehmer benötigen jeweils einen eigenen Kontext für den Versand und Empfang von
 *         // Nachrichten:
 *         KksSubscriber aliceSub = subscriber(aliceId, keyStoreDir);
 *         KksSubscriber bobSub = subscriber(bobId, keyStoreDir);
 *
 *         // Nun kann Alice eine Nachricht digital signieren und für Bob verschlüsseln indem sie erneuerbare Ein-
 *         // und Ausgabeströme entsprechend ihrer Verwendung dekoriert und dann die Daten mit Hilfe dieser erneuerbaren
 *         // Ströme einfach kopiert.
 *         // Der Einfachheit halber verwenden wir in diesem Beispiel Dateien, wobei anfangs lediglich die Datei
 *         // `message.txt` existieren muss - alle folgenden Dateien werden ggf. überschrieben.
 *         // Da Alice den Schlüsselbund gleichzeitig als Zertifikats-Verzeichnisdienst verwendet, kann sie Bob einfach
 *         // durch seinen Aliasnamen identifizieren:
 *         Callable<InputStream> plainIn = () -> new FileInputStream("message.txt");
 *         Callable<OutputStream> cipherOut = aliceSub.signAndEncryptTo(() -> new FileOutputStream("message.cms"),
 *                 "Bob's alias");
 *         copy(plainIn, cipherOut);
 *
 *         // ... und Bob kann die Nachricht entschlüsseln und die digitale Signatur von Alice überprüfen indem er
 *         // ebenfalls erneuerbare Ein- und Ausgabeströme quasi umgekehrt dekoriert und dann wiederum die Daten mit
 *         // Hilfe dieser erneuerbaren Ströme einfach kopiert.
 *         // Wenn die Überprüfung der digitalen Signatur fehlschlägt, dann wird die `close()`-Methode des erneuerbaren
 *         // Ausgabestroms `plainOut` eine `KksInvalidSignatureException` auslösen - dies passiert verdeckt innerhalb
 *         // des `copy(...)`-Aufrufs:
 *         Callable<InputStream> cipherIn = bobSub.decryptAndVerifyFrom(() -> new FileInputStream("message.cms"));
 *         Callable<OutputStream> plainOut = () -> new FileOutputStream("clonedmessage.txt");
 *         copy(cipherIn, plainOut);
 *     }
 * }
 * }</pre>
 *
 * @author Christian Schlichtherle
 * @see <a href="https://www.gkv-datenaustausch.de/media/dokumente/standards_und_normen/technische_spezifikationen/Anlage_16_-_Security-Schnittstelle.pdf">Anlage 16 - Security Schnittstelle (SECON) (PDF, 1.2 MB)</a>
 * @see <a href="https://www.gkv-datenaustausch.de/media/dokumente/standards_und_normen/technische_spezifikationen/Best_Practice_Security.pdf">Best Practice zur Security-Schnittstelle (PDF, 499 KB)</a>
 */
public final class KKS {

    static {
        Security.addProvider(new BouncyCastleProvider());
        Security.setProperty("crypto.policy", "unlimited");
    }

    private KKS() {
    }

    /**
     * Erzeugt einen initialisierten Schlüsselbund mit dem Inhalt aus dem gegebenen erneuerbaren Eingabestrom unter
     * Verwendung des gegebenen Passworts.
     * Der Inhalt des Eingabestroms muß dem PKCS12-Format entsprechen.
     */
    public static KeyStore keyStore(Callable<InputStream> source, Callable<char[]> password) throws KksException {
        return keyStore(source, password, "PKCS12");
    }

    /**
     * Erzeugt einen initialisierten Schlüsselbund mit dem Inhalt aus dem gegebenen erneuerbaren Eingabestrom unter
     * Verwendung des gegebenen Passworts.
     * Der Inhalt des Eingabestroms muß dem gegebenen Typ des Schlüsselbunds entsprechen.
     */
    public static KeyStore keyStore(
            Callable<InputStream> source,
            Callable<char[]> password,
            String type
    ) throws KksException {
        return call(() -> keyStore(() -> socket(source), password, type));
    }

    private static KeyStore keyStore(
            final Source source,
            final Callable<char[]> password,
            final String type
    ) throws Exception {
        final KeyStore ks = KeyStore.getInstance(type);
        final char[] pwChars = password.call();
        try {
            source.acceptReader(in -> ks.load(in, pwChars));
        } finally {
            Arrays.fill(pwChars, (char) 0);
        }
        return ks;
    }

    /**
     * Erzeugt eine Identität für einen Kommunikationsteilnehmer im KKS, welche durch einen privaten Schlüssel und das
     * dazugehörige Zertifikat gekennzeichnet ist.
     * Der Schlüssel und das Zertifikat werden aus dem gegebenen Schlüsselbund unter Verwendung des gegebenen
     * Aliasnamens mit dem gegebenen Passwort geladen.
     */
    public static KksIdentity identity(KeyStore ks, String alias, Callable<char[]> password) {
        return new KeyStoreIdentity(requireNonNull(ks), requireNonNull(alias), requireNonNull(password));
    }

    /**
     * Erzeugt einen Verzeichnisdienst für Zertifikate im KKS.
     * Die Zertifikate werden aus dem gegebenen Schlüsselbund geladen.
     */
    public static KksDirectory directory(KeyStore ks) {
        return new KeyStoreDirectory(requireNonNull(ks));
    }

    /**
     * Erzeugt einen Verzeichnisdienst für Zertifikate im KKS.
     * Die Zertifikate werden aus einem LDAP-Server unter Verwendung des gegebenen Verbindungspools geladen.
     * <p>
     * Das Schema des LDAP-Servers muss Kapitel 4.6.2 "LDAP-Verzeichnis" der
     * <a href="https://www.gkv-datenaustausch.de/media/dokumente/standards_und_normen/technische_spezifikationen/Anlage_16_-_Security-Schnittstelle.pdf">Security-Schnittstelle (SECON) - Anlage 16</a>
     * entsprechen.
     *
     * @param pool Ein Pool von Verbindungen zum LDAP-Server.
     */
    public static KksDirectory directory(Callable<DirContext> pool) {
        return new LdapDirectory(requireNonNull(pool)::call);
    }

    /**
     * Erzeugt einen LDAP-Verbindungspool für den gegebenen URL.
     * Die Zertifikate werden aus einem LDAP-Server unter Verwendung des gegebenen URLs geladen.
     * Alle Verbindungen werden in einem Pool verwaltet.
     * Der LDAP-Server muss anonymen Lesezugriff erlauben.
     * <p>
     * Das Schema des LDAP-Servers muss Kapitel 4.6.2 "LDAP-Verzeichnis" der
     * <a href="https://www.gkv-datenaustausch.de/media/dokumente/standards_und_normen/technische_spezifikationen/Anlage_16_-_Security-Schnittstelle.pdf">Security-Schnittstelle (SECON) - Anlage 16</a>
     * entsprechen.
     *
     * @param url Ein URL mit dem Schema {@code ldap}.
     */
    public static KksDirectory directory(final URI url) {
        if (url.getScheme().equalsIgnoreCase("ldap")) {
            final Hashtable<String, String> e = newLdapEnvironment(url);
            return directory(() -> new InitialDirContext(e));
        } else {
            throw new UnsupportedOperationException(url.getScheme());
        }
    }

    private static Hashtable<String, String> newLdapEnvironment(final URI url) {
        final Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, url.toString());
        env.put("com.sun.jndi.ldap.connect.pool", "true");
        return env;
    }

    /**
     * Erzeugt einen Kommunikationsteilnehmer unter Verwendung der gegebenen Identität und der geordneten Liste von
     * Verzeichnisdiensten für Zertifikate im KKS.
     * Beachten Sie, dass der Kommunikationsteilnehmer KEINERLEI ZERTIFIKATE ÜBERPRÜFT, nur die digitalen Signaturen!
     */
    public static KksSubscriber subscriber(
            final KksIdentity identity,
            final KksDirectory directory,
            final KksDirectory... others) {
        final KksDirectory[] directories = new KksDirectory[others.length + 1];
        directories[0] = requireNonNull(directory);
        for (int i = 0; i < others.length; ) {
            final KksDirectory other = others[i];
            directories[++i] = requireNonNull(other);
        }
        return new KksSubscriber(requireNonNull(identity), directories);
    }

    /**
     * Kopiert einen erneuerbaren Eingabestrom zu einem erneuerbaren Ausgabestrom.
     * Um eine optimale Leistung zu erzielen, wird der Eingabestrom nebenläufig im Hintergrund gelesen.
     */
    public static void copy(Callable<InputStream> input, Callable<OutputStream> output) throws KksException {
        call(() -> {
            BIOS.copy(socket(input), socket(output));
            return null;
        });
    }

    static <T extends AutoCloseable> Socket<T> socket(Callable<T> c) {
        return c::call;
    }

    private static <V> V call(Callable<V> c) throws KksException {
        return callable(c).call();
    }

    private static <V> KksCallable<V> callable(Callable<V> c) {
        return () -> {
            try {
                return c.call();
            } catch (KksException | RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new KksException(e);
            }
        };
    }

    @SuppressWarnings("deprecation")
    static <V extends AutoCloseable> KksCallable<V> callable(Socket<V> s) {
        return callable((Callable<V>) s::get);
    }
}
