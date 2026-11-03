Alles, was die Website tut, läuft über diese API, und alles andere kann sie genauso nutzen: Skripte, Bots, Passwortmanager, ein eigener Client. Diese Instanz läuft mit shhnote {{version}}. Der Server verarbeitet ausschließlich verschlüsselte Blobs, also muss ein Client die Kryptografie selbst erledigen. Das Protokoll ist klein und durch Testvektoren festgenagelt; die [Spezifikation]({{project_url}}) beschreibt es, und die Bibliothek `shh.js` sowie `vectors/v1.json` im Quell-Repository implementieren und prüfen es.

Basis-URL: `{{api_url}}/v1`. Anfragen und Antworten sind JSON, sofern nicht anders angegeben. Kennungen von Geheimnissen reisen nur in Anfragekörpern, nie in Pfaden oder Query-Strings.

## Fehler

Jeder Fehler ist ein JSON-Objekt:

```json
{"error": {"code": "invalid_ttl", "message": "The request is not valid."}}
```

Jede Operation, die ein Geheimnis-Credential entgegennimmt, antwortet bei jedem Fehlschlag mit **404 `not_found`** und identischem Körper, egal ob das Geheimnis nie existierte, abgelaufen ist, bereits geöffnet oder gebrannt wurde oder das Credential ungültig ist. Nichts unterscheidet diese Fälle, mit Absicht.

Ratenlimits antworten mit **429 `rate_limited`** und einem `Retry-After`-Header in Sekunden. Limits gelten pro Endpunkt und pro Client; der Header ist eine Konstante, die Schwelle wird also nicht verraten.

Solange der Betreiber die Einrichtung der Instanz nicht abgeschlossen hat, antwortet jeder Endpunkt außer `GET /health` mit **503 `not_configured`**.

## `GET /health`

Bereitschaft für Monitoring, ohne Authentifizierung:

```json
{"status": "ok", "version": "{{version}}", "configured": true}
```

`status` ist `ok`, wenn die Datenbank antwortet, sonst `degraded` mit **503**. `version` ist die Serverversion. `configured` ist `false`, bis der Betreiber die Einrichtung abgeschlossen hat; bis dahin antwortet jeder andere Endpunkt mit `not_configured`. `GET /` (die API-Wurzel) antwortet mit `{"name": "shhnote", "version": "v1"}`, sobald die Instanz eingerichtet ist, und vorher mit `not_configured`; für Monitoring `/health` verwenden.

## `GET /config`

Richtlinie der Instanz, ohne Authentifizierung. Vor dem Erstellen eines Geheimnisses lesen: Die Auffüllrichtlinie bestimmt, welche Blob-Längen der Server akzeptiert.

```json
{
  "fragment_version": 1,
  "padding": {"mode": "padme", "min": 65536},
  "inline_max": 2097152,
  "max_blob_bytes": 67108864,
  "claim_window_secs": 900,
  "min_ttl_secs": 60,
  "max_ttl_secs": 1209600,
  "default_ttl_secs": 86400,
  "ttl_presets": [900, 1800, 3600, 21600, 43200, 86400, 259200, 604800, 1209600],
  "text_max_bytes": 65536,
  "files_enabled": true,
  "regions": [],
  "server_version": "{{version}}",
  "web_mode": "full"
}
```

`padding.mode` ist `padme` (mit Minimum) oder `buckets` (mit einer `ladder` erlaubter Größen). `max_blob_bytes` ist die größte aufgefüllte Größe, die diese Instanz speichert. `text_max_bytes` und `files_enabled` sind Hinweise für Benutzeroberflächen; der Server prüft nur Größen. `regions` listet die Schwesterinstanzen des Betreibers als `{"code", "name", "url"}`-Objekte, leer, wenn es keine gibt. `server_version` ist die Serverversion, und `web_mode` ist `full`, wenn die Instanz ihre eigene Website ausliefert, oder `api`, wenn sie nur die API ausliefert.

## `POST /secrets`

Speichert ein Geheimnis. Der Körper ist `multipart/form-data` mit zwei Teilen in dieser Reihenfolge:

1. `meta`, JSON:

   ```json
   {
     "lookup_key": "<base64url von SHA-256(lookup)>",
     "burn_key": "<base64url von SHA-256(burn_token)>",
     "lifetime": "single_view",
     "ttl_seconds": 86400
   }
   ```

   `lifetime` ist `single_view` oder `ttl`. `ttl_seconds` muss zwischen `min_ttl_secs` und `max_ttl_secs` liegen; auch ein einmaliges Geheimnis läuft danach ab, wenn niemand es öffnet. Beide Schlüssel sind 32-Byte-SHA-256-Hashes, base64url ohne Padding: `lookup_key` ist `SHA-256(lookup)` und `burn_key` ist `SHA-256(burn_token)`, berechnet vom Client. Der Server speichert sie so, wie sie ankommen, und sieht beim Erstellen weder `lookup` noch das Brenn-Token; Aufdecken, Bestätigen, Melden und Brennen senden die ungehashten Werte, und der Server hasht sie, um das Geheimnis zu finden.

2. `blob`, der verschlüsselte Blob als Bytes. Seine Länge muss genau einer aufgefüllten Größe entsprechen, die die Instanz akzeptiert.

Antwortet mit **201** und leerem Körper, auch wenn ein Geheimnis mit diesem `lookup_key` bereits existiert (dann wird nichts geschrieben; eine andere Antwort würde jedem, der einen Hash besitzt, verraten, ob das Geheimnis noch da ist). Fehler: `invalid_meta`, `invalid_lookup_key`, `invalid_burn_key`, `invalid_lifetime`, `invalid_ttl`, `invalid_blob_length`, `invalid_multipart` (400, der Körper besteht nicht aus zwei Teilen namens `meta` und `blob` in dieser Reihenfolge); `files_disabled` (400, die Instanz nimmt nur textgroße Geheimnisse an); `too_large` (413); `request_timeout` (408, der Körper kam zu langsam an); `too_busy` (503 mit `Retry-After`, zu viele Uploads gleichzeitig); `storage_full` (507, die Instanz hat gerade keinen Platz für große Geheimnisse); `api_key_required` (401, siehe unten).

## `POST /secrets/reveal`

```json
{"lookup": "<base64url des Lookup-Werts>"}
```

Liefert den Blob als `application/octet-stream` mit `Cache-Control: no-store`.

Bei einem **einmaligen** Geheimnis verbraucht der erste erfolgreiche Aufruf es und liefert den Header `X-Shh-Claim-Token`. Innerhalb von `claim_window_secs` darf derselbe Client den Blob erneut laden, indem er `{"lookup": …, "claim_token": "<dieser Header>"}` sendet; ein abgebrochener Download lässt sich so wiederholen. Niemand sonst kann das.

Bei einem **TTL**-Geheimnis ist die Antwort der Blob und sonst nichts: kein Claim-Token und nichts über die verbleibende Lebensdauer.

## `POST /secrets/confirm`

```json
{"lookup": "<base64url>", "claim_token": "<Token aus reveal>"}
```

Teilt dem Server mit, dass der Client ein einmaliges Geheimnis entschlüsselt hat, wodurch es vor Ablauf des Abruffensters zerstört wird. **204** bei Erfolg. Optional, aber höflich.

## `POST /secrets/burn`

```json
{"burn_token": "<base64url des Brenn-Tokens>"}
```

Zerstört ein aktives Geheimnis. Nur wer es erstellt hat, besitzt das Brenn-Token; der Teilen-Link enthält keine Brenn-Berechtigung. **204** bei Erfolg.

## `POST /reports`

```json
{"lookup": "<base64url des Lookup-Werts>"}
```

Wer einen Link hat, darf ihn melden. Ist das Geheimnis aktiv, wird es sofort entfernt. Immer **200** mit `{"status": "received"}`, was auch immer geschah. Die Meldung wird in der Statistik des Tages gezählt; welches Geheimnis gemeldet wurde, wird nicht festgehalten.

## API-Schlüssel

Anfragen können `Authorization: Bearer <Schlüssel>` tragen. Ein Schlüssel mit dem Bereich `user` verlagert das Ratenlimit von der Netzwerkadresse auf den Schlüssel, mit höheren Limits, und ist auf entsprechend konfigurierten Instanzen zum Erstellen von Geheimnissen erforderlich. Schlüssel vergibt der Betreiber im Admin-Bereich; sie werden nie mit einem Geheimnis verknüpft.

## Einen Client bauen

Der schnellste Weg ist das Modul `shh.js`, das jede Instanz unter `/static/shh.js` ausliefert und das auch unter Node läuft. Es fasst den gesamten Ablauf in vier Aufrufen zusammen und nimmt eine fetch-Implementierung deiner Wahl:

```js
import { Argon2, createSecret, revealSecret, burnSecret } from "./shh.js";

const api = { apiBase: "{{api_url}}/v1" };
const { fragment, burnFragment } = await createSecret({
  ...api,
  payload: { text: "das Passwort ist hunter2", files: [] },
  lifetime: "single_view",
  ttlSeconds: 86400,
});
console.log(`{{site_url}}/s#${fragment}`);

const { payload } = await revealSecret(`#${fragment}`, api);
await burnSecret(`#${burnFragment}`, api); // jetzt 404: es war einmalig
```

Mit Passphrase geschützte Geheimnisse brauchen zusätzlich `argon2: await Argon2.load(wasmBytes)` mit dem Modul von `/static/argon2.wasm`. Eine Passphrase ist eine nicht-leere Zeichenkette: `""` wird abgewiesen (`empty_passphrase`), und nur das Weglassen der Option bedeutet „keine Passphrase“. Schlägt etwas fehl, nachdem ein Einmal-Geheimnis beansprucht wurde (falsche Passphrase, abgebrochene Verbindung), trägt der Fehler ein `claimToken`; wird es beim nächsten Versuch als `claimToken` übergeben, wird das Geheimnis erneut geladen statt verloren zu gehen. `confirm: false` liefert es bei Erfolg zum selben Zweck zurück.

Leite die Werte, die die API erwartet, aus dem 32-Byte-Seed im Teilen-Link ab: `lookup = HKDF-SHA-256(seed, info "shhnote/lookup/v1")`, base64url-kodiert gesendet. Das Brenn-Token sind separate zufällige 32 Bytes, die der Ersteller behält. Beim Erstellen werden stattdessen ihre Hashes gesendet: `lookup_key = SHA-256(lookup)` und `burn_key = SHA-256(burn_token)`. Blob-Aufbau, Schlüsselumhüllung, Chunking und Auffüllung sind in der [Protokollspezifikation]({{project_url}}) festgelegt und durch deren Konformitätsvektoren byteweise festgeschrieben; ein Client, der sie reproduziert, ist mit jeder Instanz kompatibel. Wie du eine eigene Instanz betreibst, beschreibt [das Projekt]({{project_url}}).
