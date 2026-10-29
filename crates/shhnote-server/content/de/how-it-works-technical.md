> Hier steht, wie Geheimnisse geschützt werden sollen. Der Text wird mit dem Code abgeglichen, während die Funktionen entstehen.

## Verschlüsselung

Wenn du ein Geheimnis erstellst, nutzt dein Browser die eingebaute [Web Crypto API](https://developer.mozilla.org/de/docs/Web/API/Web_Crypto_API):

1. Er erzeugt einen zufälligen 256-Bit-Schlüssel mit einem kryptografisch sicheren Zufallszahlengenerator.
2. Er verschlüsselt deine Notiz und jede Datei mit **AES-256-GCM**, jeweils mit einer neuen zufälligen Nonce. GCM erkennt außerdem jede Veränderung der verschlüsselten Daten.
3. Er lädt nur die verschlüsselten Daten (den Geheimtext) hoch, zusammen mit der Ablaufzeit und der Einstellung „Nach dem Lesen löschen“.

## Der Schlüssel bleibt im Link

Der Schlüssel steht im **Fragment** des Links, also im Teil nach `#`, zum Beispiel `/s/abc123#schluessel`. Browser senden das Fragment nie an den Server, daher taucht der Schlüssel weder in Anfragen noch in Server-Protokollen oder im Referrer auf. Der Server sieht immer nur die ID des Geheimnisses.

## Passphrasen

Wenn du eine Passphrase festlegst, wird daraus mit **PBKDF2-SHA-256** ein zweiter Schlüssel abgeleitet, mit zufälligem Salt und vielen Durchläufen, um das Erraten zu verlangsamen. Das Geheimnis lässt sich nur mit beidem entschlüsseln: dem Schlüssel aus dem Link und der Passphrase. Die Passphrase wird nie an den Server gesendet.

## Speicherung

Der Server speichert den Geheimtext, die Ablaufzeit und die Einstellungen. Kleine Geheimnisse liegen in der Datenbank; größere Dateien je nach Einrichtung des Servers auf der Festplatte oder in S3-kompatiblem Speicher. Abgelaufene Geheimnisse werden gelöscht, und Geheimnisse mit „Nach dem Lesen löschen“ sobald sie abgerufen werden.

## Ein Geheimnis öffnen

Die Seite des Geheimnisses lädt nichts, bis die empfangende Person auf **Geheimnis anzeigen** klickt. So können Link-Vorschauen ein einmaliges Geheimnis nicht verbrauchen. Danach lädt der Browser den Geheimtext herunter, liest den Schlüssel aus dem Fragment und entschlüsselt alles lokal.

## Schutzmaßnahmen im Browser

Jede Seite wird mit einer strengen Content Security Policy ausgeliefert: Skripte und Styles dürfen nur von unserem eigenen Server kommen, und eingebettete Skripte sind blockiert. Seiten können nicht in andere Websites eingebettet werden, und die Referrer-Richtlinie verhindert, dass die Adresse des Geheimnisses anderswohin gesendet wird. Seiten mit Geheimnissen sind so markiert, dass Browser und Proxys sie nie zwischenspeichern.

## Was der Server sehen kann

Der Server kann deine Geheimnisse nicht lesen, sieht aber wie jede Website einige Angaben: wann ein Geheimnis erstellt und geöffnet wurde, seine ungefähre Größe und die beteiligten IP-Adressen. Wenn dir das wichtig ist, nutze ein VPN oder Tor.
