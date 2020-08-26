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
 * import java.security.cert.*;
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
 *         KeyStore ks = keyStore(() -> new FileInputStream("keystore.p12"), "secret"::toCharArray);
 *
 *         // Außerdem benötigen beide Kommunikationsteilnehmer einen eigenen Kontext für den Versand und Empfang von
 *         // Nachrichten:
 *         KksSubscriber alice = subscriber(ks, "Alice's alias", "Alice's password"::toCharArray);
 *         KksSubscriber bob = subscriber(ks, "Bob's alias", "Bob's password"::toCharArray);
 *
 *         // Außerdem benötigen wir ein Zertifikat, das den Nachrichtenempfänger repräsentiert.
 *         // In diesem Fall können wir das Zertifikat einfach aus dem Kontext für Bob entnehmen.
 *         // Da der Zugriff auf Bob's Zertifikat eine beliebige `Exception` auslösen kann, verwenden wir `call(...)` um
 *         // diese ggf. in eine `KksException` zu verpacken:
 *         X509Certificate bobsCert = call(bob::myCertificate);
 *
 *         // Nun kann Alice eine Nachricht digital signieren und für Bob verschlüsseln indem sie erneuerbare Ein-
 *         // und Ausgabeströme entsprechend ihrer Verwendung dekoriert und dann die Daten mit Hilfe dieser erneuerbaren
 *         // Ströme einfach kopiert.
 *         // Der Einfachheit halber verwenden wir in diesem Beispiel Dateien, wobei anfangs lediglich die Datei
 *         // `message.txt` existieren muss - alle folgenden Dateien werden ggf. überschrieben:
 *         Callable<InputStream> plainIn = () -> new FileInputStream("message.txt");
 *         Callable<OutputStream> cipherOut = alice.signAndEncryptTo(() -> new FileOutputStream("message.cms"),
 *                 bobsCert);
 *         copy(plainIn, cipherOut);
 *
 *         // ... und Bob kann die Nachricht entschlüsseln und die digitale Signatur von Alice überprüfen indem er
 *         // ebenfalls erneuerbare Ein- und Ausgabeströme quasi umgekehrt dekoriert und dann wiederum die Daten mit
 *         // Hilfe dieser erneuerbaren Ströme einfach kopiert.
 *         // Wenn die Überprüfung der digitalen Signatur fehlschlägt, dann wird die `close()`-Methode des erneuerbaren
 *         // Ausgabestroms `plainOut` eine `KksInvalidSignatureException` auslösen - dies passiert verdeckt innerhalb
 *         // des `copy(...)`-Aufrufs:
 *         Callable<InputStream> cipherIn = bob.decryptAndVerifyFrom(() -> new FileInputStream("message.cms"));
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
     * Erzeugt einen neuen Schlüsselbund, initialisiert ihn mit dem Inhalt aus dem gegebenen erneuerbaren Eingabestrom
     * unter Verwendung des gegebenen Passworts und gibt ihn zurück.
     * Der Inhalt des Eingabestroms muß dem PKCS12-Format entsprechen.
     * Diese Komfortfunktion ist für den Gebrauch mit {@link #subscriber(KeyStore, String, Callable, Callable)}
     * vorgesehen.
     */
    public static KeyStore keyStore(Callable<InputStream> source, Callable<char[]> password) throws KksException {
        return keyStore(source, password, "PKCS12");
    }

    /**
     * Erzeugt einen neuen Schlüsselbund, initialisiert ihn mit dem Inhalt aus dem gegebenen erneuerbaren Eingabestrom
     * unter Verwendung des gegebenen Passworts und gibt ihn zurück.
     * Der Inhalt des Eingabestroms muß dem gegebenen Typ des Schlüsselbunds entsprechen.
     * Diese Komfortfunktion ist für den Gebrauch mit {@link #subscriber(KeyStore, String, Callable, Callable)}
     * vorgesehen.
     */
    public static KeyStore keyStore(
            final Callable<InputStream> source,
            final Callable<char[]> password,
            final String type
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
     * Erzeugt einen LDAP-Verbindungspool für den gegebenen URL und gibt ihn zurück.
     * Der LDAP-Server muss anonymen Lesezugriff erlauben.
     */
    public static Callable<DirContext> ldapConnectionPool(final String url) {
        if (!url.regionMatches(true, 0, "ldap://", 0, 7)) {
            throw new IllegalArgumentException(url);
        }
        final Hashtable<String, String> e = newLdapEnvironment(url);
        return () -> new InitialDirContext(e);
    }

    private static Hashtable<String, String> newLdapEnvironment(final String url) {
        final Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, url);
        env.put("com.sun.jndi.ldap.connect.pool", "true");
        return env;
    }

    /**
     * Gibt einen Kommunikationsteilnehmer zurück, der durch den gegebenen Eintrag mit dem privaten Schlüssel und dem
     * gegebenen Passwort in dem gegebenen Schlüsselbund repräsentiert wird.
     * <p>
     * Beachten Sie, dass der zurückgegebene Kommunikationsteilnehmer KEINERLEI ZERTIFIKATE ÜBERPRÜFT, nur die digitalen
     * Signaturen!
     *
     * @see #keyStore(Callable, Callable)
     * @see #ldapConnectionPool(String)
     */
    public static KksSubscriber subscriber(KeyStore ks, String alias, Callable<char[]> password) {
        return subscriber(ks, alias, password, () -> {
            throw new KksCertificateNotFoundException("No LDAP configured");
        });
    }

    /**
     * Gibt einen Kommunikationsteilnehmer zurück, der durch den gegebenen Eintrag mit dem privaten Schlüssel und dem
     * gegebenen Passwort in dem gegebenen Schlüsselbund repräsentiert wird.
     * Der gegebene LDAP-Verbindungspool wird für den Zugriff auf die Zertifikate verwendet, falls diese nicht im
     * Schlüsselbund gefunden werden.
     * Das Schema des LDAP-Servers muss Kapitel 4.6.2 "LDAP-Verzeichnis" der
     * <a href="https://www.gkv-datenaustausch.de/media/dokumente/standards_und_normen/technische_spezifikationen/Anlage_16_-_Security-Schnittstelle.pdf">Security-Schnittstelle (SECON) - Anlage 16</a>
     * entsprechen.
     * <p>
     * Beachten Sie, dass der zurückgegebene Kommunikationsteilnehmer KEINERLEI ZERTIFIKATE ÜBERPRÜFT, nur die digitalen
     * Signaturen!
     *
     * @see #keyStore(Callable, Callable)
     * @see #ldapConnectionPool(String)
     */
    public static KksSubscriber subscriber(
            KeyStore ks,
            String alias,
            Callable<char[]> password,
            Callable<DirContext> ldapConnectionPool
    ) {
        return new LdapSubscriber(requireNonNull(ks), requireNonNull(alias), requireNonNull(password),
                ldapConnectionPool::call);
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
