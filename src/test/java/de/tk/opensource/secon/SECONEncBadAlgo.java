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
package de.tk.opensource.secon;

import static java.util.Objects.requireNonNull;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.security.KeyStore;
import java.security.Security;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.concurrent.Callable;

import javax.naming.Context;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import global.namespace.fun.io.api.Socket;
import global.namespace.fun.io.bios.BIOS;

/**
 * Stellt CMS-Dienste (Cryptographic Message Syntax) für das Krankenkassenkommunikationssystem (SECON) bereit.
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
 * import de.tk.opensource.secon.*;
 *
 * import static de.tk.opensource.secon.SECON.*;
 *
 * class Scratch {
 *
 *     public static void main(String... unused) throws SeconException {
 *         // Wir benötigen einen Schlüsselbund mit jeweils einem eigenen privaten Schlüsselbund-Eintrag für Alice und
 *         // Bob:
 *         KeyStore keyStore = keyStore(() -> new FileInputStream("keystore.p12"), "secret"::toCharArray);
 *
 *         // Als nächstes erzeugen beide Kommunikationsteilnehmer jeweils eine eigene Identität:
 *         Identity aliceId = identity(keyStore, "Alice's alias", "Alice's password"::toCharArray);
 *         Identity bobId = identity(keyStore, "Bob's alias", "Bob's password"::toCharArray);
 *
 *         // Außerdem verwenden beide Kommunikationsteilnehmer denselben Schlüsselbund als Verzeichnisdienst für
 *         // Zertifikate:
 *         Directory keyStoreDir = directory(keyStore);
 *
 *         // Beide Kommunikationsteilnehmer benötigen jeweils einen eigenen Kontext für den Versand und Empfang von
 *         // Nachrichten:
 *         Subscriber aliceSub = subscriber(aliceId, keyStoreDir);
 *         Subscriber bobSub = subscriber(bobId, keyStoreDir);
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
 *         // Ausgabestroms `plainOut` eine `InvalidSignatureException` auslösen - dies passiert verdeckt innerhalb
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
public final class SECONEncBadAlgo {

    static {
        Security.addProvider(new BouncyCastleProvider());
        Security.setProperty("crypto.policy", "unlimited");
    }

    private SECONEncBadAlgo() {
    }

    /**
     * Erzeugt einen initialisierten Schlüsselbund mit dem Inhalt aus dem gegebenen erneuerbaren Eingabestrom unter
     * Verwendung des gegebenen Passworts.
     * Der Inhalt des Eingabestroms muß dem PKCS12-Format entsprechen.
     */
    public static KeyStore keyStore(Callable<InputStream> input, Callable<char[]> password) throws SeconException {
        return keyStore(input, password, "PKCS12");
    }

    /**
     * Erzeugt einen initialisierten Schlüsselbund mit dem Inhalt aus dem gegebenen erneuerbaren Eingabestrom unter
     * Verwendung des gegebenen Passworts.
     * Der Inhalt des Eingabestroms muß dem gegebenen Typ des Schlüsselbunds entsprechen.
     */
    public static KeyStore keyStore(
            Callable<InputStream> input,
            Callable<char[]> password,
            String type
    ) throws SeconException {
        return call(() -> keyStore(socket(input), password, type));
    }

    private static KeyStore keyStore(
            final Socket<InputStream> input,
            final Callable<char[]> password,
            final String type
    ) throws Exception {
        final KeyStore ks = KeyStore.getInstance(type);
        final char[] pwChars = password.call();
        try {
            input.accept(in -> ks.load(in, pwChars));
        } finally {
            Arrays.fill(pwChars, (char) 0);
        }
        return ks;
    }

    /**
     * Erzeugt eine Identität für einen Kommunikationsteilnehmer im SECON mittels eines privaten Schlüssels und des
     * dazugehörigen Zertifikats.
     * Der Schlüssel und das Zertifikat werden aus dem gegebenen Schlüsselbund unter Verwendung des gegebenen
     * Aliasnamens mit dem gegebenen Passwort geladen.
     * <p>
     * Beim Entschlüsseln von Nachrichten wird der Schlüsselbund nach passenden privaten Schlüsseln durchsucht.
     * Das gegebene Passwort muss daher zu <em>allen</em> privaten Schlüsseln im Schlüsselbund passen.
     */
    public static Identity identity(KeyStore ks, String alias, Callable<char[]> password) {
        return new KeyStoreIdentity(requireNonNull(ks), requireNonNull(alias), requireNonNull(password));
    }

    /**
     * Erzeugt einen Verzeichnisdienst für Zertifikate von Kommunikationsteilnehmern im SECON.
     * Die Zertifikate werden aus dem gegebenen Schlüsselbund geladen.
     */
    public static Directory directory(KeyStore ks) {
        return new KeyStoreDirectory(requireNonNull(ks));
    }

    /**
     * Erzeugt einen Verzeichnisdienst für Zertifikate von Kommunikationsteilnehmern im SECON.
     * Die Zertifikate werden aus einem LDAP-Server unter Verwendung des gegebenen Verbindungspools geladen.
     * <p>
     * Das Schema des Directory Information Tree muss Kapitel 4.6.2 "LDAP-Verzeichnis" der
     * <a href="https://www.gkv-datenaustausch.de/media/dokumente/standards_und_normen/technische_spezifikationen/Anlage_16_-_Security-Schnittstelle.pdf">Security-Schnittstelle (SECON) - Anlage 16</a>
     * entsprechen.
     *
     * @param pool Ein Pool von Verbindungen zum LDAP-Server.
     */
    public static Directory directory(Callable<DirContext> pool) {
        return new LdapDirectory(requireNonNull(pool)::call);
    }

    /**
     * Erzeugt einen LDAP-Verbindungspool für den gegebenen URL.
     * Die Zertifikate werden aus einem LDAP-Server unter Verwendung des gegebenen URLs geladen.
     * Alle Verbindungen werden in einem Pool verwaltet.
     * Der LDAP-Server muss anonymen Lesezugriff erlauben und das Schema des Directory Information Tree muss Kapitel
     * 4.6.2 "LDAP-Verzeichnis" der
     * <a href="https://www.gkv-datenaustausch.de/media/dokumente/standards_und_normen/technische_spezifikationen/Anlage_16_-_Security-Schnittstelle.pdf">Security-Schnittstelle (SECON) - Anlage 16</a>
     * entsprechen.
     *
     * @param url Ein URL mit dem Schema {@code ldap}.
     */
    public static Directory directory(final URI url) {
        if (url.getScheme().equalsIgnoreCase("ldap")) {
            final Hashtable<String, String> e = ldapEnvironment(url);
            return directory(() -> new InitialDirContext(e));
        } else {
            throw new UnsupportedOperationException(url.getScheme());
        }
    }

    private static Hashtable<String, String> ldapEnvironment(final URI url) {
        final Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, url.toString());
        env.put("com.sun.jndi.ldap.connect.pool", "true");
        return env;
    }

    /**
     * Erzeugt einen Kommunikationsteilnehmer im SECON unter Verwendung der gegebenen Identität und der geordneten Liste
     * von Verzeichnisdiensten für Zertifikate.
     */
    public static Subscriber subscriber(
            final Identity identity,
            final Directory directory,
            final Directory... others) {
        final Directory[] directories = new Directory[others.length + 1];
        directories[0] = requireNonNull(directory);
        for (int i = 0; i < others.length; ) {
            final Directory other = others[i];
            directories[++i] = requireNonNull(other);
        }
        return new DefaultSubscriberEncBadAlgo(requireNonNull(identity), directories);
    }

    /**
     * Kopiert einen erneuerbaren Eingabestrom zu einem erneuerbaren Ausgabestrom.
     * Um eine optimale Leistung zu erzielen, wird der Eingabestrom nebenläufig im Hintergrund gelesen.
     */
    public static void copy(Callable<InputStream> input, Callable<OutputStream> output) throws SeconException {
        call(() -> {
            BIOS.copy(socket(input), socket(output));
            return null;
        });
    }

    static <T extends AutoCloseable> Socket<T> socket(Callable<T> c) {
        return c::call;
    }

    private static <V> V call(Callable<V> c) throws SeconException {
        return callable(c).call();
    }

    private static <V> SeconCallable<V> callable(Callable<V> c) {
        return () -> {
            try {
                return c.call();
            } catch (final Exception e) {
                rethrow(e);
                if (e instanceof RuntimeException) {
                    throw (RuntimeException) e;
                } else {
                    throw new SeconException(e);
                }
            }
        };
    }

    private static void rethrow(Throwable t) throws SeconException {
        for (; null != t; t = t.getCause()) {
            if (t instanceof SeconException) {
                throw (SeconException) t;
            }
        }
    }

    @SuppressWarnings("deprecation")
    static <V extends AutoCloseable> SeconCallable<V> callable(Socket<V> s) {
        return callable((Callable<V>) s::get);
    }
}
