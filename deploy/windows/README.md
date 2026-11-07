# Service Windows NoLog

Le projet produit actuellement une DLL d’enclave. Pour utiliser NSSM, il faut
un exécutable hôte Windows qui charge cette DLL.

Le script peut utiliser une copie locale de NSSM ou la télécharger uniquement
si `-DownloadNssm` est fourni. La source officielle est
<https://www.nssm.cc/download>.

Installation sans téléchargement automatique :

```powershell
.\NoLog-Service.ps1 -Action Install `
  -NssmPath C:\Tools\nssm\win64\nssm.exe `
  -ExecutablePath C:\NoLog\NoLogHost.exe `
  -WorkingDirectory C:\NoLog `
  -StartAfterInstall
```

Installation avec téléchargement explicite :

```powershell
.\NoLog-Service.ps1 -Action Install `
  -DownloadNssm `
  -ExecutablePath C:\NoLog\NoLogHost.exe
```

Gestion :

```powershell
.\NoLog-Service.ps1 -Action Status
.\NoLog-Service.ps1 -Action Start
.\NoLog-Service.ps1 -Action Stop
.\NoLog-Service.ps1 -Action Restart
.\NoLog-Service.ps1 -Action Uninstall
```

Le service utilise `NT AUTHORITY\LocalService` et redémarre après une sortie
anormale. Le mot de passe du vault DPAPI doit être initialisé sous le même
compte de service ; aucun mot de passe de service n’est passé sur la ligne de
commande.

## Gestion Docker

Pour gérer PostgreSQL et le dashboard depuis PowerShell :

```powershell
.\NoLog-Stack.ps1 -Action Up
.\NoLog-Stack.ps1 -Action Status
.\NoLog-Stack.ps1 -Action Logs -Service dashboard
.\NoLog-Stack.ps1 -Action Restart
.\NoLog-Stack.ps1 -Action Down
```

Tor reste optionnel :

```powershell
.\NoLog-Stack.ps1 -Action Up -Tor
```
