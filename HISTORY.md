# Änderungshistorie

Diese Datei fasst die in den Skript- und Moduldateien dokumentierten Änderungen
chronologisch zusammen. Die Versionsnummern beziehen sich jeweils auf die
genannte Komponente und stellen nicht immer eine gemeinsame Release-Version dar.

## 2024

### 2024-02-18

- **TierLevelUserManagement.ps1** (`0.2.20240218`): Dokumentation aktualisiert.
  Diese Versionsangabe steht in der Quelldatei vor den als initial bezeichneten
  Versionen vom Dezember 2024 und könnte daher ein Datumsfehler sein.

### 2024-12-06

- **install.ps1** (`0.2.20241206`): Initiale Version.
- **TierLevelUserManagement.ps1** (`0.2.20241206`): Initiale Version.

### 2024-12-20

- **TierLevelComputerManagement.ps1** (`20241220`): Initiale Version.
- **TierLevelUserManagement.ps1** (`0.2.20241220`): Beim Entfernen eines
  Benutzers aus einer privilegierten Gruppe wird `adminCount` entfernt.
  Benutzer in einer Service-Account-OU werden nicht aus privilegierten Gruppen
  entfernt.

### 2024-12-23

- **TierLevelComputerManagement.ps1** (`20241223`): Dokumentation ergänzt.
  Debug-Protokollierung im Benutzerdatenverzeichnis und wichtige Ereignisse im
  Anwendungsprotokoll dokumentiert.
- **TierLevelUserManagement.ps1** (`20241223`): Dokumentation aktualisiert.

## 2025

### 2025-01-03

- **install.ps1** (`0.2.20250103`): Tippfehler korrigiert.

### 2025-01-06

- **install.ps1** (`0.2.20250106`): Computergruppen in Servergruppen
  umbenannt. Der Name der Tier-1-Servergruppe kann geändert werden. Tier-X-User-
  OUs wurden in Tier-X-Admin-OUs umbenannt. Der angezeigte GPO-Name basiert nun
  auf der Variable `$GPOName`.

### 2025-01-09

- **install.ps1** (`0.2.20250109`): Benötigte Gruppen werden auf dem nächsten
  globalen Katalog erstellt. Das Skript wartet auf die Replikation der
  Computergruppe und bricht ab, wenn die Gruppe nicht erstellt werden kann.

### 2025-02-17

- **install.ps1** (`0.2.20250217`): Installation wird abgebrochen, wenn eine
  benötigte OU nicht erstellt werden kann. Fehlermeldungen wurden erweitert.

### 2025-02-18

- **install.ps1** (`0.2.20250218`): Ausgabetexte aktualisiert.

### 2025-02-28

- **install.ps1** (`0.2.20250228`): Fehler bei der OU-Erstellung und Tippfehler
  behoben.

### 2025-03-03

- **install.ps1** (`0.2.20250303`): Fehler beim Aktualisieren der XML-Datei für
  geplante Aufgaben behoben.

### 2025-03-04

- **TierLevelComputerManagement.ps1** (`0.2.20250304`): Pfad der Protokolldatei
  wird in der Startmeldung ausgegeben.
- **TierLevelUserManagement.ps1** (`0.2.20250304`): Pfad der Protokolldatei wird
  in der Startmeldung ausgegeben.

### 2025-03-06

- **install.ps1** (`0.2.20250306`): Neu erstellte Tier-0- und
  Tier-1-Servergruppen erhalten `adminCount = 1`.

### 2025-03-13

- **install.ps1** (`0.2.20250313`): Fehler im Anspruch der
  Tier-0-Kerberos-Authentifizierungsrichtlinie behoben. Beschreibungen für die
  Tier-0- und Tier-1-Kerberos-Authentifizierungsrichtlinien ergänzt.

### 2025-03-14

- **install.ps1** (`0.2.20250314`): Das GMSA wird bei Bedarf der Gruppe
  `Enterprise Admins` hinzugefügt.
- **TierLevelComputerManagement.ps1** (`0.2.20250314`): Dokumentation
  aktualisiert.
- **TierLevelUserManagement.ps1** (`0.2.20250314`): Debug-Informationen
  ergänzt. Fehler beim Hinzufügen zur Gruppe `Protected Users` behoben und
  Prüfung auf bestehende Mitgliedschaft ergänzt.

### 2025-03-15

- **TierLevelIsolation.psm1** (`0.1.20250315`): Initiale Modulversion.

### 2025-03-20

- **install.ps1** (`0.2.20250320`): Standardname der Konfigurationsdatei von
  `Tiering.config` in `TierLevelIsolation.config` geändert.
- **TierLevelComputerManagement.ps1** (`0.2.20250320`): Standardname der
  Konfigurationsdatei von `tiering.json` in `TierLevelIsolation.config`
  geändert.
- **TierLevelUserManagement.ps1** (`0.2.20250320`): Standardname der
  Konfigurationsdatei von `tiering.config` in `TierLevelIsolation.config`
  geändert.

### 2025-03-27

- **install.ps1** (`0.2.20250327`): Konfiguration wird nun über das
  PowerShell-Modul erstellt. Fehler in `New-TierLevelOU` behoben. Installation
  des Moduls und Parameter für eine reine Modulinstallation ergänzt.
- **TierLevelIsolation.psm1** (`0.1.20250327`): Funktionen zur Verwaltung der
  Tier-Level-Isolation-Konfiguration ergänzt und Fehler behoben.
  `Add-TierLevelIsolationDomain` akzeptiert nun ein Array als Eingabe.
- **TierLevelUserManagement.ps1** (`0.2.20250327`): Standardwert des Parameters
  `$ConfigFile` korrigiert.

### 2025-03-29

- **TierLevelComputerManagement.ps1** (`0.2.20250329`): Protokollpfad wird aus
  der Konfigurationsdatei gelesen.

### 2025-03-31

- **install.ps1** (`0.2.20250331`): Gruppenrichtlinie wird importiert, damit
  Änderungen an geplanten Aufgaben übernommen werden. Die Aufgabe zum Wechsel
  des Ausführungskontexts wird im GPO erstellt. Benutzeraufgaben sind im GPO
  standardmäßig deaktiviert. Modulfehler behoben.
- **TierLevelIsolation.psm1** (`0.1.20250331`): Parameter `Path` der Funktionen
  für Computer-, Benutzer- und Service-Account-Pfade in `OU` umbenannt.
  OU-Existenzprüfung und Fehlerbehandlung für ungültige AD-Objekte ergänzt.

### 2025-04-10

- **TierLevelUserManagement.ps1** (`0.2.20250410`): Erkennung relativer DNs
  privilegierter Benutzer in `ValidateAndRemoveUser` korrigiert.

### 2025-04-23

- **TierLevelIsolation.psm1** (`0.1.20250423`): Funktionen zum Lesen und Setzen
  des Debug-Protokollpfads ergänzt.
- **TierLevelUserManagement.ps1** (`0.2.20250423`): Wenn kein alternativer
  Protokollpfad konfiguriert ist, wird das lokale AppData-Verzeichnis des
  ausführenden Benutzers verwendet.

### 2025-04-28

- **install.ps1** (`0.2.20250428`): Parameter `-Force` für das Setzen der
  Computergruppe und der Kerberos-Authentifizierungsrichtlinie ergänzt. Die
  Lösung verwendet nun grundsätzlich ein GMSA.
- **TierLevelIsolation.psm1** (`0.2.20250428`): Parameter `-Force` für
  `Set-TierLevelIsolationComputerGroup` und
  `Set-TierLevelIsolationKerberosAuthenticationPolicy` ergänzt.

### 2025-06-19

- **TierLevelUserManagement.ps1** (`0.2.20250619`): Fehler beim Schreiben in
  das Ereignisprotokoll behoben.

### 2025-06-23

- **TierLevelComputerManagement.ps1** (`0.2.20250623`): Fehlerbehandlung für
  fehlende oder fehlerhafte Konfigurationsdateien und neuer Exitcode ergänzt.
- **TierLevelUserManagement.ps1** (`0.2.20250623`): Verwendung des Parameters
  `ConfigFile` korrigiert und zusätzliche Exitcodes ergänzt.

### 2025-06-25

- **install.ps1** (`0.2.20250625`): GMSA-Validierung ergänzt; Namen mit mehr
  als 15 Zeichen werden abgelehnt.
- **TierLevelComputerManagement.ps1** (`0.2.20250625`): Einlesen der
  Konfigurationsdatei an `TierLevelUserManagement.ps1` angeglichen.

### 2025-07-14

- **install.ps1** (`0.2.20250714`): Fehler bei ausschließlicher Verwendung von
  Tier 0 behoben.
- **TierLevelComputerManagement.ps1** (`0.2.20250714`): Fehler bei der
  Verarbeitung des Parameters `Scope` behoben.
- **TierLevelUserManagement.ps1** (`0.2.20250714`): Fehler bei der Verarbeitung
  des Parameters `Scope` behoben.

### 2025-09-23

- **install.ps1** (`0.2.20250923`): Kerberos Claim Support kann manuell
  aktiviert werden; das Skript zeigt dazu eine Warnung an.

### 2025-10-14

- **install.ps1** (`0.2.20251014`): Links zur Microsoft-Dokumentation für
  Kerberos Authentication Policies, Claims und Kerberos Armoring aktualisiert.

### 2025-12-02

- **TierLevelComputerManagement.ps1** (`0.2.20251202`): Fehlerbehandlung für
  nicht verfügbare Active Directory Web Services bei der Prüfung unerwarteter
  Computerobjekte ergänzt. Start mit dem Parameter `ConfigFile` korrigiert.

### 2025-12-19

- **TierLevelIsolation.psm1** (`0.2.20251219`): Funktionen zum Hinzufügen und
  Entfernen zusätzlicher Tier-0- und Tier-1-Gruppen ergänzt.
- **TierLevelUserManagement.ps1** (`0.2.20251219`):
  `ConvertTo-DistinguishedNames` zur Umwandlung relativer OU-Pfade in FQDNs
  ergänzt. Verarbeitung privilegierter Domänengruppen aus der Konfiguration
  ergänzt.

### 2025-12-23

- **TierLevelIsolation.psm1** (`0.2.20251223`): Eine Gruppe kann nicht Tier 1
  hinzugefügt werden, wenn sie bereits Tier 0 zugeordnet ist. Gruppenidentitäten
  unterstützen NetBIOS-, UPN- und kanonische Schreibweise.
- **TierLevelUserManagement.ps1** (`0.2.20251223`): Benennung der Scopes
  `Tier-0` und `Tier-1` korrigiert.

### 2025-12-24

- **TierLevelUserManagement.ps1** (`0.2.20251224`): Dokumentation aktualisiert
  und Verhalten des Parameters `AddProtectedUsersGroup` in
  `Set-TierLevelIsolation` angepasst.

### 2025-12-26

- **TierLevelUserManagement.ps1** (`0.2.20251226`): Verarbeitung der Gruppe
  `Protected Users` korrigiert.

## 2026

### 2026-01-20

- **install.ps1** (`0.2.20260120`): Fehler bei der Auswahl des Tier Levels
  behoben.

### 2026-03-06

- **install.ps1** (`0.2.20260306`): In der Quelldatei ist für diese Version
  keine Änderungsbeschreibung dokumentiert.
- **TierLevelComputerManagement.ps1** (`0.2.20260306`): Codedokumentation und
  Struktur überarbeitet. Dateinamen der Protokolle enthalten Scope und
  Computername zur besseren Unterscheidung in gemeinsam verwendeten Pfaden.
- **TierLevelUserManagement.ps1** (`0.2.20260306`): Codedokumentation und
  Struktur überarbeitet. Dateinamen der Protokolle enthalten Scope und
  Computername. Ereignis-ID `2001` ergänzt.

### 2026-03-17

- **TierLevelUpdateModule.ps1** (`0.1.20260317`): Initiale Version.

### 2026-08-25

- **install.ps1** (`0.2.20260825.1`): Konfiguration von `Protected Users` wird
  nur noch im erweiterten Setupmodus angezeigt.
- **install.ps1** (`0.2.20260825.2`): Konfiguration des Debug-Protokollpfads zum
  erweiterten Setupmodus hinzugefügt.
- **install.ps1** (`0.2.20260825.3`): Aktuelle Domäne wird bei der OU-Prüfung
  angezeigt. Werte einer vorhandenen Konfiguration werden als Setupvorgaben
  verwendet.
- **TierLevelComputerManagement.ps1** (`0.2.20260825.1`): Ereignis-IDs und
  Ereignisquellen an die Windows-Event-Log-Richtlinien angeglichen.
- **TierLevelIsolation.psm1** (`0.1.20260825.1`): Persistierung des
  Debug-Protokollpfads korrigiert.
- **TierLevelIsolation.psm1** (`0.1.20260825.2`): Zusätzliche Tier-0- und
  Tier-1-Gruppen werden anhand ihrer SID gespeichert. Befehl zur Anzeige der
  konfigurierten zusätzlichen Gruppen ergänzt.
- **TierLevelUpdateModule.ps1** (`0.1.20260825.1`): Version für die initiale
  Veröffentlichung des Repositorys aktualisiert.
- **TierLevelUserManagement.ps1** (`0.2.20260825.1`): Ereignis-IDs und
  Ereignisquellen an die Windows-Event-Log-Richtlinien angeglichen.
- **TierLevelUserManagement.ps1** (`0.2.20260825.2`): SID-basierte Bereinigung
  zusätzlicher Tier-0- und Tier-1-Gruppen ergänzt.
- **TierLevelUserManagement.ps1** (`0.2.20260825.3`): `adminCount` wird bei der
  Verarbeitung von Tier-0-Gruppen für verschachtelte Gruppen auf `1` gesetzt.
- **TierLevelUserManagement.ps1** (`0.2.20260825.4`): DNS-Serverauflösung für
  verschachtelte Gruppen korrigiert.

### 2026-08-28

- **install.ps1** (`0.2.20260828.1` bis `0.2.20260828.5`): Eindeutiges und
  detailliertes Installationsprotokoll im Temp-Verzeichnis ergänzt. Vollständige
  Code-Dokumentation, ZIP-Export des PowerShell-Moduls in das Documents-
  Verzeichnis und nicht interaktive Parametrisierung über ein PowerShell-Objekt
  hinzugefügt. Die Tier-0-Bezeichnung wurde auf „Tier 0 computer“ vereinheitlicht.
- **TierLevelIsolation.psm1** (`0.1.20260828.1` bis `0.1.20260828.2`):
  Vollständige Modul-, Funktions- und Inline-Dokumentation ergänzt.
- **TierLevelIsolation.psd1** (`0.1.20260828.2`): Manifestversion,
  PowerShell-Mindestversion und Release Notes aktualisiert.
- **TierLevelUserManagement.ps1** (`0.2.20260828.1`): `adminCount` wird für
  verschachtelte Tier-0-Gruppen explizit eingelesen, bevor eine erforderliche
  Aktualisierung vorgenommen wird.