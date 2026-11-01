## Wie wir deine Geheimnisse schützen

- **Im Browser verschlüsselt.** Deine Notiz und Dateien werden auf deinem Gerät verschlüsselt, bevor sie hochgeladen werden. Der Schlüssel steht nur in deinem Link, wir haben ihn also nie.
- **Weg, wenn du es willst.** Geheimnisse werden gelöscht, wenn sie ablaufen, oder sobald sie geöffnet werden, wenn du „Nach dem Lesen löschen“ wählst.
- **Optionale Passphrase.** Sie schützt zusätzlich, sodass ein weitergegebener Link allein nicht reicht.
- **Strenge Schutzmaßnahmen im Browser.** Unsere Seiten laden Code nur von unserem eigenen Server, können nicht in andere Websites eingebettet werden und verraten anderen Websites nie, woher du kommst.

## Was wir nicht versprechen können

- **Speicher in deinem Browser.** Nachdem ein Geheimnis angezeigt wurde, überschreibt die Seite beim Verlassen, was sie kann. JavaScript kann das nicht garantieren, dein Browser kann entschlüsselte Daten also im Speicher behalten, bis der Tab geschlossen wird. Schließ den Tab, wenn du fertig bist.
- **Automatisierte Klicks.** Die Anzeigeseite lädt nichts, bevor jemand wirklich klickt oder eine Taste drückt. Ein Link-Scanner oder eine Browser-Erweiterung, die echte Eingaben erzeugt, wie ein Mensch es täte, kann ein einmaliges Geheimnis öffnen. Die Empfängerin sieht dann, dass es bereits geöffnet wurde, und das ist das ehrliche Ergebnis: Etwas anderes hat es gelesen.
- **Reste nach dem Löschen.** Löschen entfernt den Eintrag. Verschlüsselte Reste können in Datenbank-Journalen, freiem Speicherplatz oder Backups verbleiben, bis sie überschrieben werden. Es ist Chiffretext ohne Schlüssel.
- **Zeitstempel großer Dateien.** Große Geheimnisse, die außerhalb der Datenbank liegen, tragen den Zeitpunkt, zu dem die Datei geschrieben wurde; das hält der Speicher von sich aus fest.

## Tipps zum sicheren Teilen

- Schick die Passphrase auf einem anderen Weg als den Link, zum Beispiel den Link per E-Mail und die Passphrase am Telefon.
- Wähle die kürzeste Ablaufzeit, die für dich passt.
- Nutze „Nach dem Lesen löschen“ für Passwörter und andere einmalige Informationen.

## Sicherheitslücke melden

Wenn du glaubst, ein Sicherheitsproblem gefunden zu haben, schreib bitte an {{security_email}} und informiere uns vertraulich, bevor du es anderen erzählst. Beschreibe, was du gefunden hast und wie es sich nachvollziehen lässt.

Wir werden:

- innerhalb von [Anzahl] Werktagen antworten;
- dich auf dem Laufenden halten, während wir es beheben;
- dich bei der Veröffentlichung der Lösung nennen, wenn du möchtest.

Bitte greif beim Testen nicht auf Daten anderer zu, stör den Dienst nicht und führ keine automatischen Scans durch, die ihn stark belasten.

Sicherheitslücken in der shhnote-Software selbst: siehe [{{project_url}}/security]({{project_url}}/security).
