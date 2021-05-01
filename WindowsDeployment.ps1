<#
Autor: Tobias Hösli
Letzte Änderungen: 29.04.2021

Dieses Script führt folgende Aufgaben aus:

Konfigurationen:
    -Windows Festplatte in "System" umbenennen
    -Anzeigen von "Dieser PC" auf Desktop
    -Anzeigen des Benutzerordners auf Dektop
    -Taskansicht-Schaltfläche Ausschalten
    -Kontakte auf der Taskleiste Ausschalten
    -Suchsymbol auf der Taskleiste aktivieren
    -Benutzerkontensteuerung Ausschalten
    -Kleine Symbole in Systemsteuerung festlegen
    -Defragmentierung Ausschalten
    -Appvorschläge Ausschalten
    -ScmartScreen deaktivieren
    -Windows Light-Mode deaktivieren
    -Zuletzt hinzugefügte Apps ausschalten
    -Explorer öffnen für "Dieser PC"
    -Alle Icons werden von der Taskleiste gelöst
    -Tastaturlayout Französisch (Schweiz) & Deutsch (Deutschland) löschen
    -Gelegentliche Appvorschläge ausschalten                    
    -Löschen von "Fax" und "Microsoft XPS Document Writer" Druckern 
    -Uhrzeit Synchronisieren

Rausputzen:
    -Windows Apps
    -Alle Verknüpfungen auf dem Desktop Löschen
    -Temporäre Dateien

Diverses:
    -Windows Aktivierung
    -Wiederherstellungspunkt
    -ToDO Liste

#>

#--------------------------------------------------------------------------

#Script mit Adminrechten neustarten
Function Adminneustart {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
		Exit
	}
}
Adminneustart

#--------------------------------------------------------------------------

$ConfirmPreference = “None”
$ErrorActionPreference = "SilentlyContinue"

#chocolatey installieren (Packagemanager)
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) | Out-Null
choco feature enable -n allowGlobalConfirmation

#--------------------------------------------------------------------------
clear


#Windows Festplatte zu "System" umbenennen
Function Festplatteumbenennen {
    Write-Output "Windows Festplatte wird umbenannt..."
    Set-Volume -DriveLetter C -NewFileSystemLabel "System"
}
Festplatteumbenennen

#Anzeigen von "Dieser PC" auf Desktop
Function DieserPCaufDesktop {
	Write-Output "Dieser PC wird auf den Desktop hinzugefügt..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
}
DieserPCaufDesktop

#Anzeigen des Benutzerordners auf Dektop
Function BenutzerordneraufDesktop {
    Write-Output "Benutzerordner wird auf den Desktop hinzugefügt..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
}
BenutzerordneraufDesktop

#Taskansicht-Schaltfläche Ausschalten
Function TaskansichtschaltflächeAusschalten {
    Write-Output "Taskansicht-Schaltfläche wird entfernt..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
}
TaskansichtschaltflächeAusschalten

#Kontakte auf der Taskleiste Ausschalten 
Function KontakteIconAusschalten {
    Write-Output "Kontakte Icon wird von der Taskleiste entfernt..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
}
KontakteIconAusschalten

#Suchsymbol auf der Taskleiste aktivieren
Function SuchsymbolEinschalten {
	Write-Output "Showing Taskbar Search icon..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1
}
SuchsymbolEinschalten

#Benutzerkontensteuerung Ausschalten
Function UACAusschalten {
	Write-Output "Benutzerkontensteuerung wird ausgeschalten..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0
}
UACAusschalten

#Kleine Symbole in Systemsteuerung festlegen
Function SystemsteuerungKleineSymbole {
	Write-Output "Kleine Symbole werden in Systemsteuerung festgelegt..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 1
}
SystemsteuerungKleineSymbole

#Defragmentierung Ausschalten
Function DefragmentierungAusschalten {
	Write-Output "Defragmentierung wird ausgeschalten..."
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}
DefragmentierungAusschalten

#Appvorschläge Ausschalten
Function Appvorschlägeausschalten {
	Write-Output "Gelegentliche Appvorschläge werden ausgeschalten..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1 | Out-Null
}
Appvorschlägeausschalten

#ScmartScreen deaktivieren
Function Smartscreendeaktivieren {
	Write-Output "SmartScreen wird deaktiviert..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0
}
Smartscreendeaktivieren

#Windows Light-Mode deaktivieren
Function lightmodedeaktivieren {
	Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name SystemUsesLightTheme -Value 0 -Type Dword -Force
}
lightmodedeaktivieren

#Zuletzt hinzugefügte Apps ausschalten
Function Zuletzthinzugefügtausschalten {
    Write-Output "Zuletzt hinzugefügte Apps werden ausgeschalten..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 1
    }
Zuletzthinzugefügtausschalten

#Explorer für "Dieser PC" Öffnen
Function ExplorerfürDieserPC {
	Write-Output "Setze Explorer öffnen für Dieser PC..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
}
ExplorerfürDieserPC

#Alle Icons werden von der Taskleiste gelöst
Function Taskleisteniconslöschen {
	Write-Output "Icons werden von Taskleiste gelöst..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "Favorites" -Type Binary -Value ([byte[]](255))
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesResolve" -ErrorAction SilentlyContinue
}
Taskleisteniconslöschen

#Französisch (Schweiz) & Deutsch (Deutschland) löschen
Function löschetastaturen {
    Write-Output "Französisch (Schweiz) Tastaturlayout wird entfernt..."
    $langs = Get-WinUserLanguageList
    Set-WinUserLanguageList ($langs | ? {$_.LanguageTag -ne "fr-CH"}) -Force
    Write-Output "Deutsch (Deutschland) Tastaturlayout wird entfernt..."
    $langs = Get-WinUserLanguageList
    Set-WinUserLanguageList ($langs | ? {$_.LanguageTag -ne "de-DE"}) -Force
    }
löschetastaturen

#Löschen von "Fax" und "Microsoft XPS Document Writer" Druckern 
Function LöscheDrucker {
	Write-Output "Fax Drucker wird entfernt..."
	Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
    Write-Output "Microsoft XPS Document Writer Drucker wird entfernt..."
    Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null
}
LöscheDrucker

#Synchronisierung der Uhrzeit
Function Uhrzeit {
    Write-Output "Uhrzeit wird synchronisiert..."
    net stop w32time >$null 2>&1
    net start w32time >$null 2>&1
    W32tm /config /manualpeerlist:time.windows.com,0x8 /syncfromflags:MANUAL >$null 2>&1
    W32tm /config /update >$null 2>&1
}
Uhrzeit

#---------------------------------------------------------------------------

#Windows Media Player öffnen
Function MediaPlayer {
    Write-Output "Windows Media Player wird geöffnet..."
    Set-Location "C:\Program Files\Windows Media Player"
    .\wmplayer.exe
}
MediaPlayer
#---------------------------------------------------------------------------

Write-Output ""

#Löschen von allen Windows Apps, ausser Store
Function MSAppslöschen {
    Write-Output "Windows Apps werden deinstalliert..."
    Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingTranslator" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Microsoft3DViewer" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftPowerBIForWindows" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MinecraftUWP" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.MSPaint" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.NetworkSpeedTest" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.OneConnect" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Print3D" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.RemoteDesktop" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
	Get-AppxPackage "2414FC7A.Viber" | Remove-AppxPackage
	Get-AppxPackage "41038Axilesoft.ACGMediaPlayer" | Remove-AppxPackage
	Get-AppxPackage "46928bounde.EclipseManager" | Remove-AppxPackage
	Get-AppxPackage "4DF9E0F8.Netflix" | Remove-AppxPackage
	Get-AppxPackage "64885BlueEdge.OneCalendar" | Remove-AppxPackage
	Get-AppxPackage "7EE7776C.LinkedInforWindows" | Remove-AppxPackage
	Get-AppxPackage "828B5831.HiddenCityMysteryofShadows" | Remove-AppxPackage
	Get-AppxPackage "89006A2E.AutodeskSketchBook" | Remove-AppxPackage
	Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
	Get-AppxPackage "A278AB0D.DisneyMagicKingdoms" | Remove-AppxPackage
	Get-AppxPackage "A278AB0D.MarchofEmpires" | Remove-AppxPackage
	Get-AppxPackage "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage
	Get-AppxPackage "AdobeSystemsIncorporated.AdobePhotoshopExpress" | Remove-AppxPackage
	Get-AppxPackage "CAF9E577.Plex" | Remove-AppxPackage
	Get-AppxPackage "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage
	Get-AppxPackage "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage
	Get-AppxPackage "DB6EA5DB.CyberLinkMediaSuiteEssentials" | Remove-AppxPackage
	Get-AppxPackage "DolbyLaboratories.DolbyAccess" | Remove-AppxPackage
	Get-AppxPackage "Drawboard.DrawboardPDF" | Remove-AppxPackage
	Get-AppxPackage "Facebook.Facebook" | Remove-AppxPackage
	Get-AppxPackage "flaregamesGmbH.RoyalRevolt2" | Remove-AppxPackage
	Get-AppxPackage "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage
	Get-AppxPackage "KeeperSecurityInc.Keeper" | Remove-AppxPackage
	Get-AppxPackage "king.com.BubbleWitch3Saga" | Remove-AppxPackage
	Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
	Get-AppxPackage "PandoraMediaInc.29680B314EFC2" | Remove-AppxPackage
	Get-AppxPackage "SpotifyAB.SpotifyMusic" | Remove-AppxPackage
	Get-AppxPackage "WinZipComputing.WinZipUniversal" | Remove-AppxPackage
	Get-AppxPackage "XINGAG.XING" | Remove-AppxPackage
    Get-AppxPackage *solitairecollection* | Remove-AppxPackage
}
MSAppslöschen

#Alle Verknüpfungen auf dem Desktop Löschen
Function LöscheEdgevonDekstop {
    Write-Output "Alle Verknüpfungen auf dem Desktop werden gelöscht..."
    Remove-Item "C:\Users\*\Desktop\*.lnk" }
LöscheEdgevonDekstop


#Löschen von Temporären Windows Dateien / chocolatey Dateien
Function Tempslöschen {
    Write-Output "Temporäre Dateien werden gelöscht..."
    $folders = @("C:\Windows\Temp\*", "C:\Users\*\Appdata\Local\Temp\*", "C:\Windows\SoftwareDistribution\Download", "C:\Windows\System32\FNTCACHE.DAT", "C:\Users\*\Documents\WindowsPowerShell", "C:\ProgramData\chocolatey")
    foreach ($folder in $folders) {Remove-Item $folder -force -recurse -ErrorAction SilentlyContinue}
}
Tempslöschen

#--------------------------------------------------------------------------

#Windows Aktivierung
Write-Output "Windows wird aktiviert..."
slmgr -ato

#ToDoList erstellen
Write-Output "ToDoListe wird erstellt..."
cd C:\Users\$env:UserName\Desktop | Out-Null
new-item -name ToDo.txt -type "file" -value "-Updates überprüfen `n-Firefox und Microsoft Edge Konfigurieren `n-Start & Taskleiste Anpassen `nExplorer:`n   -Falls HDD, Defragmentierung aktivieren `n   -Explorer Menüband herunterklappen `n   -Evtl. Datenschutzeinstellungen ändern `n-App-Symbole & Benachrichtigungen ausschalten `n-Standardprogramme festlegen `n-Standardprogramme & Apps Kontrollieren `n-OneDrive beim Starten nicht ausführen `n-Treiberupdatesoftware ausführen `n-ToDo.txt löschen `n-Wiederherstellungspunkt erstellen" –force | Out-Null

#ToDoList öffnen
C:\Users\$env:UserName\Desktop\ToDo.txt

#Wiederherstellungpunkt erstellen
Checkpoint-Computer -Description „Omikron Data AG Scriptfix“ -RestorePointType „MODIFY_SETTINGS“
Write-Output "Wiederherstellungspunkt wird erstellt..."



