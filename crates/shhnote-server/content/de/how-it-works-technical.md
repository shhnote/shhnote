> Hier wird das Protokoll aus `SPEC.md` beschrieben, dem Dokument, nach dem der Code gebaut wird. Wo beide abweichen, hat die Spezifikation recht und der Code einen Fehler.

## Ein Geheimnis erstellen

Alles Folgende passiert in deinem Browser mit der eingebauten [Web Crypto API](https://developer.mozilla.org/de/docs/Web/API/Web_Crypto_API). Der Server führt nichts davon aus.

1. Dein Browser erzeugt einen zufälligen 256-Bit-**Seed** und einen davon unabhängigen zufälligen 256-Bit-**Inhaltsschlüssel**.
2. Dein Text und deine Dateien werden zu einer Nutzlast zusammengefasst: ein kleines Manifest (Dateinamen, Typen und Größen), gefolgt von den Dateibytes.
3. Die Nutzlast wird auf eine **Größenklasse aufgefüllt**, sodass der Server nur eine grobe Größe erfährt, nie die genaue. Das Standardverfahren (Padmé) fügt höchstens 12 % hinzu und rundet jedes Geheimnis auf mindestens 64 KiB auf, sodass ein Passwort und eine kleine Datei gleich aussehen.
4. Die aufgefüllte Nutzlast wird in 64-KiB-Blöcken mit **AES-256-GCM** unter dem Inhaltsschlüssel verschlüsselt. Jeder Block hat eine eigene Nonce und ein eigenes Authentifizierungs-Tag, und der letzte Block ist markiert, sodass Manipulation, Umsortieren oder Abschneiden erkannt wird.
5. Der Inhaltsschlüssel wird mit einem per HKDF-SHA-256 aus dem Seed abgeleiteten Schlüssel **verpackt** (verschlüsselt). Mit Passphrase wird der Verpackungsschlüssel aus dem Seed *und* einer Argon2id-Streckung der Passphrase abgeleitet, sodass beides nötig ist.
6. Nur der verschlüsselte Blob wird hochgeladen. Er hat exakt denselben Aufbau, ob eine Passphrase gesetzt wurde oder nicht, sodass der Server es nicht erkennen kann.

## Der Seed bleibt im Link

Der Link sieht so aus: `/s#<Version><Seed>`. Alles nach dem `#` ist das **Fragment**, das Browser nie an einen Server senden. Der Seed taucht also weder in Anfragen noch in Server-Protokollen oder im Referrer auf. Die Seite `/s` selbst ist für jedes Geheimnis identisch.

Um das Geheimnis zu finden, leitet dein Browser aus dem Seed einen separaten **Suchwert** ab (wieder per HKDF, also nicht umkehrbar) und sendet diesen. Der Server speichert davon nur einen SHA-256-Hash. Dasselbe gilt für jedes Zugangsdatum, das der Server kennt: Eine Kopie der Datenbank enthält nichts, womit sich ein Geheimnis lesen, verbrauchen oder zerstören ließe.

## Passphrasen

Eine Passphrase wird mit **Argon2id** gestreckt (standardmäßig 64 MiB Speicher, 3 Durchläufe), mit einem zufälligen Salt, das im Blob gespeichert ist. Das Ergebnis wird mit dem Seed zum Verpackungsschlüssel kombiniert. Die Passphrase wird nirgendwohin gesendet. Dein Browser versucht zuerst, den Inhaltsschlüssel ohne Passphrase zu entpacken; nur wenn das fehlschlägt, fragt er dich danach. Deshalb zeigt die Seite kein Passphrase-Feld, bevor es gebraucht wird.

## Was der Server speichert

Den verschlüsselten Blob, wann er abläuft, ob er einmalig oder zeitbegrenzt ist, und Hashes der Such- und Brenn-Zugangsdaten. Blobs bis zu einigen Megabyte liegen in der Datenbank, größere auf der Festplatte oder in S3-kompatiblem Speicher, je nach Betrieb der Instanz. Es gibt keinen Erstellungszeitpunkt, keine Aufzeichnung, wer etwas erstellt oder geöffnet hat, und keinen Aufrufzähler. Es werden nur Gesamtsummen geführt, nie mit einem Geheimnis verknüpft.

## Ein Geheimnis öffnen

Die Seite lädt nichts, bevor du auf den Button klickst, sodass Link-Vorschauen und E-Mail-Scanner ein einmaliges Geheimnis nicht verbrauchen können. Ein **einmaliges** Geheimnis gilt in dem Moment als verbraucht, in dem seine Bytes ausgeliefert werden: Bricht dein Download ab, kann dein Browser ihn innerhalb von fünfzehn Minuten erneut abrufen, niemand sonst, und danach ist es weg. Ein **zeitbegrenztes** Geheimnis lässt sich bis zum Ablauf öffnen. In beiden Fällen wird der Blob lokal entschlüsselt, mit dem Seed aus dem Fragment.

## Brennen

Beim Erstellen eines Geheimnisses bekommst du auch einen **Brenn-Link**, gebildet aus einem separaten zufälligen Token, das der Server nur als Hash kennt. Den Brenn-Link zu öffnen bewirkt allein nichts; erst das Bestätigen zerstört das Geheimnis. Nur die erstellende Person hat ihn. Wer den Teilen-Link hat, kann ein Geheimnis melden, was es ebenfalls entfernt.

## Schutzmaßnahmen im Browser

Jede Seite wird mit einer strengen Content Security Policy ausgeliefert: Skripte und Styles nur von unserem eigenen Server, keine eingebetteten Skripte. Seiten können nicht in andere Websites eingebettet werden, der Referrer wird nie gesendet, und die Anzeigeseite wird nie zwischengespeichert. Alle Ressourcen liegen auf unserem Server; der Client stellt keine Anfragen an andere Ursprünge.

## Was der Server sehen kann

Der Server kann deine Geheimnisse nicht lesen, sieht aber wie jede Website jede Anfrage in dem Moment, in dem sie passiert: den Zeitpunkt, die Größenklasse des Blobs und die IP-Adresse, von der sie kommt. Davon behält er nichts. Wenn dir selbst das wichtig ist, nutze ein VPN oder Tor.
