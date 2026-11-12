# Hannah Asset Server

HTTP-Server für statische Assets (Sounds, Bilder, Videos) der Hannah-Plattform. Clients laden Assets per Key herunter und cachen sie lokal; Änderungserkennung über SHA256-Manifest.

## Stack

- Go 1.25, `CGO_ENABLED=0`
- `modernc.org/sqlite` (kein CGO)
- Docker `scratch`-Image, multi-arch (amd64 + arm64)
- Volume `/data` für DB + Dateien

## Namespaces

DB-verwaltet, editierbar über die WebUI (Admin → Namespaces) oder `/api/namespaces`. Beim ersten Start werden `shared` (Wurzel) sowie `core` und `satellite` als dessen Kinder angelegt.

**Ein Asset lebt in genau einem Namespace** — es gibt keinen Multi-Tag mehr. Ein Namespace kann einen `parent` haben und "erweitert" ihn:

- **Vererbung**: Wer `read` auf einen Namespace hat, sieht beim Manifest-/Download-Abruf automatisch auch alle Assets der Eltern-Kette mit — kein zusätzliches Recht auf den Parent nötig.
- **Überschreiben**: Ein Kind-Namespace "überschreibt" einen von einem Vorfahren geerbten Key einfach dadurch, dass er selbst einen Upload mit demselben Key bekommt (`PUT /namespaces/{ns}/assets/{key}`) — es gibt keinen separaten Override-Mechanismus mehr, Hochladen ist immer derselbe Vorgang. Beim Auflösen gewinnt immer die spezifischste Ebene (Kind vor Parent vor Großeltern).

Beispiel: Ein Sound, der sowohl `core` als auch `satellite` gemeinsam ist, wird in `shared` hochgeladen und ist danach automatisch in beiden sichtbar. `satellite-test` mit `parent: satellite` sieht alle `satellite`-Assets (und damit transitiv auch `shared`), kann aber einzelne Sounds testweise durch eigene Versionen ersetzen, ohne Produktion (`satellite`) zu beeinflussen.

Ein Namespace lässt sich nur löschen, wenn kein Asset mehr direkt darin liegt und keine Kind-Namespaces mehr existieren.

### ⚠️ Breaking Change gegenüber älteren Versionen

Frühere Versionen kannten einen globalen `key` (ein Asset konnte mehreren Namespaces gleichzeitig zugeordnet sein) und einen separaten Override-Mechanismus für Kind-Namespaces. Das ist jetzt vereinheitlicht:

- `namespace` ist bei **Download und Manifest jetzt Pflichtparameter** — der alte Aufruf ohne `?namespace=` funktioniert nicht mehr.
- Der Multi-Namespace-Upload (`PUT /assets/{key}?namespaces=a,b`) und das Umtaggen (`PATCH /assets/{key}/namespaces`) sind entfallen, ersetzt durch den einzigen Upload-Endpunkt `PUT /namespaces/{ns}/assets/{key}`.
- Bestehende Daten werden beim Update automatisch migriert (Assets, die vorher gleichzeitig in `core` und `satellite` lagen, landen in `shared`), aber **Clients müssen angepasst werden**, um `namespace` bei jedem Aufruf mitzugeben.

## Auth

### Menschliche Nutzer

Login über WebUI (`/`) mit Username/Passwort oder OIDC/OAuth2 (optional, z.B. Keycloak).  
Session als HTTP-Only-Cookie `hannah_session`.

### Maschinenclients (Service Accounts)

`Authorization: Bearer <token>` — Token wird beim Erstellen einmalig im Plaintext zurückgegeben.  
Berechtigungen werden direkt am Service Account konfiguriert: Namespace + Action (`read`/`write`).

### RBAC (für menschliche Nutzer)

```
Users → Groups → Roles → Permissions (Namespace + Action)
```

Admin-Flag per User — Admins haben vollen Zugriff ohne Rollenkonfiguration.

### OAuth2 / OIDC

Wird optional über die WebUI konfiguriert (Admin → OAuth2-Tab). Der Redirect-URL wird automatisch aus dem Request (`X-Forwarded-Proto` + `Host`) abgeleitet.

**Keycloak Group Sync**: Wenn der ID-Token einen `groups`-Claim enthält, werden die Gruppenmitgliedschaften des Users bei jedem Login mit den DB-Gruppen abgeglichen (Full Replace). Keycloak-Setup: „Group Membership"-Mapper mit Token Claim Name `groups`, Full group path **aus**.

## Environment Variables

| Variable | Default | Beschreibung |
|---|---|---|
| `PORT` | `8080` | HTTP-Port |
| `STORAGE_PATH` | `/data` | Verzeichnis für DB + Asset-Dateien |
| `DB_PATH` | `$STORAGE_PATH/assets.db` | SQLite-Pfad |
| `ADMIN_PASSWORD` | — | Bootstrapt Admin-User beim ersten Start (kein User in DB) |
| `INSECURE_COOKIE` | — | Auf `true` setzen für HTTP ohne TLS (dev) |
| `MAX_IMPORT_BYTES` | `2147483648` | Maximale Größe eines Import-Bundles (Bytes) |
| `REQUIRE_NON_ROOT` | — | Auf `true` setzen: Server bricht ab, wenn er nicht auf uid 1000 wechseln kann (statt als root weiterzulaufen). Siehe [Container-User](#container-user) |

## API

### Public

| Method | Path | Beschreibung |
|---|---|---|
| `GET` | `/health` | `ok` |
| `GET` | `/api/config` | `{"oauth2_enabled": bool}` |

### Assets (Auth required)

| Method | Path | Beschreibung |
|---|---|---|
| `GET` | `/manifest?namespace=<ns>` | Manifest für Namespace inkl. geerbter Parent-Assets (`namespace` Pflicht) |
| `GET` | `/assets/{key}?namespace=<ns>` | Asset herunterladen — löst entlang der Namespace-Kette auf, spezifischste Ebene gewinnt (`namespace` Pflicht) |
| `PUT` | `/namespaces/{ns}/assets/{key}` | Asset hochladen / ersetzen — der einzige Upload-Endpunkt (write-Recht auf `ns`) |
| `DELETE` | `/namespaces/{ns}/assets/{key}` | Asset löschen |
| `GET` | `/namespaces/{ns}/assets` | Assets auflisten, die direkt in `ns` liegen (nicht geerbt) |
| `GET` | `/api/assets` | Alle Assets über alle Namespaces (JSON, admin: alle; sonst nur erlaubte) |
| `GET` | `/api/export?namespace=<ns>[&keys=a,b]` | Assets, die direkt in `ns` liegen, als `.tar.gz`-Bundle streamen (read-Recht auf `ns`) |
| `POST` | `/api/import?namespace=<ns>[&overwrite=true]` | Bundle (Request-Body) importieren (write-Recht auf `ns`), Antwort ist ein JSON-Ergebnisbericht |

### Export / Import

Zum Weitergeben von Assets an andere Asset-Server (kein Pull, nur Datei-Austausch). In der WebUI: Namespace-Filter wählen → **Export**; auf dem Ziel-Server **Import**.

- **Bundle**: `.tar.gz`, erster Eintrag `manifest.json` (`format`, `namespace`, Assets mit `key`, `mime_type`, `sha256`, `size`), danach `files/<key>`. Exportiert werden nur Assets, die direkt im Namespace liegen — geerbte nicht. Metadaten (Dauer, Auflösung etc.) werden beim Import neu extrahiert.
- **Ziel-Namespace**: Default ist der Name aus dem Bundle, per `namespace=` überschreibbar. Existiert er nicht, wird er angelegt — nur für Admins (Root-Namespace ohne Parent), sonst `400`.
- **Konflikte**: Gleicher Key + gleicher SHA256 → `unchanged`. Gleicher Key + anderer Inhalt → `conflicts` (übersprungen), außer `overwrite=true`. Jede Datei wird gegen den SHA256 im Manifest geprüft.
- **Größe**: `MAX_IMPORT_BYTES` begrenzt das Bundle; der Import streamt ohne Zwischendatei.

### Manifest-Format

```json
{
  "version": 1,
  "generated_at": "2026-05-31T12:00:00Z",
  "assets": {
    "confirmation_sound": {
      "namespace": "shared",
      "sha256": "e3b0c44298fc1c14...",
      "size": 12345,
      "mime": "audio/mpeg"
    }
  }
}
```

`namespace` zeigt an, aus welcher Ebene der Kette der Eintrag tatsächlich aufgelöst wurde (der anfragende Namespace selbst oder einer seiner Vorfahren).

### Upload

```
PUT /namespaces/shared/assets/confirmation_sound
Authorization: Bearer <token>
Content-Type: audio/mpeg

<binary body>
```

### Client-Sync-Algorithmus

```
1. GET /manifest?namespace={eigener_namespace}
2. Für jeden Key im Manifest:
   a. Lokale Datei vorhanden und SHA256 stimmt → skip
   b. Sonst: GET /assets/{key}?namespace={eigener_namespace} → auf Disk speichern
3. Optional: lokale Dateien löschen die nicht mehr im Manifest sind
```

`namespace` ist bei Schritt 2b **Pflicht** — ohne Parameter lehnt der Server die Anfrage ab (siehe Breaking-Change-Hinweis oben).

### Admin-API (Kurzübersicht)

| Prefix | Beschreibung |
|---|---|
| `/api/users` | User-CRUD |
| `/api/groups` | Gruppen-CRUD + Members + Roles |
| `/api/roles` | Rollen-CRUD + Assignments |
| `/api/namespaces` | Namespace-CRUD (Name, Parent, Description) |
| `/api/service-accounts` | Service Accounts + Tokens + Permissions |
| `/api/oauth2/config` | OAuth2-Konfiguration |

## Deployment

Docker Compose Beispiel:

```yaml
services:
  asset-server:
    image: registry.example.com/hannah-asset-server:latest
    environment:
      ADMIN_PASSWORD: changeme
    volumes:
      - asset-data:/data
    ports:
      - "8080:8080"

volumes:
  asset-data:
```

### Container-User

Der Server-Prozess läuft als **uid/gid 1000:1000**, nicht als root.

Das Image ist `FROM scratch` (keine Shell, kein `chown`-Entrypoint) und bestehende Volumes wurden früher von root beschrieben. Deshalb startet der Container zunächst als root, übergibt `STORAGE_PATH` (rekursiv) an `1000:1000` und wechselt dann den Benutzer — bevor Datenbank und HTTP-Listener geöffnet werden. Das passiert automatisch beim ersten Start nach dem Update; Daten gehen nicht verloren, ein manueller Schritt ist nicht nötig. Folgestarts prüfen nur das Top-Level-Verzeichnis. Neue Dateien gehören ab dann uid 1000. Neue Volumes sind von Anfang an korrekt.

- **Bereits als Nicht-root gestartet** (z. B. `user: "1000:1000"` im Compose): die Migration entfällt. Das Volume muss dann einmalig `1000:1000` gehören, z. B. `docker run --rm -v <volume>:/data alpine chown -R 1000:1000 /data`.
- **Wechsel nicht möglich** (NFS mit `root_squash`, entzogene Capabilities, …): der Server läuft mit einer Warnung im Log weiter als root, sodass nach dem Update nichts ausfällt. Mit `REQUIRE_NON_ROOT=true` bricht er stattdessen mit einer Fehlermeldung ab. Abhilfe: Ownership einmalig auf dem Storage setzen (siehe oben).
- **`DB_PATH` außerhalb von `STORAGE_PATH`**: dieses Verzeichnis wird nicht migriert und muss für uid 1000 schreibbar sein.

> **Ausblick:** Ein späteres Release setzt `USER 1000:1000` direkt im Image und entfernt die Migration. Volumes sollten bis dahin einmal mit dieser Version gestartet worden sein, sonst bricht der Start mit „permission denied“ ab.

## Entwicklung

```bash
cd app
go run .
```

Für lokale Entwicklung ohne HTTPS:

```bash
INSECURE_COOKIE=true go run .
```

CI baut das Docker-Image automatisch bei Push auf `master` (multi-arch via Kaniko).
