# VMware Workstation Simplified Chinese Packages

Deploy Simplified Chinese resources to a local VMware Workstation installation, with automatic backup and restore.

## Structure

```
VMware-Workstation-zh_CN/
  17-official-zh_CN/   Official 17.6.4 Simplified Chinese resources (x86) + official tray
  full-zh_CN/          26H1u1 complete localization (x64) + patched Chinese tray
  deploy.ps1           Auto-detect install path, select package/tray, request UAC, deploy
  restore.ps1          Select a backup and restore the previous state
  README.md
```

## Compatibility

| Package | Target | Architecture | Tray |
| --- | --- | --- | --- |
| `17-official-zh_CN` | VMware Workstation 17.x | x86 | Official 17.6.4 tray, optional |
| `full-zh_CN` | VMware Workstation 26.x (verified 26H1u1 / 26.0.1 build 25688693) | x64 | Patched 26H1u1 tray, optional |

`deploy.ps1` reads the PE machine type of the installed `vmware.exe` and of the package `vmui-zh_CN.dll`. Cross-architecture deployment is refused. A major version mismatch requires explicit confirmation; the full package is intended for 26.x.

## Usage

1. Close VMware Workstation and all virtual machines.
2. Run PowerShell in this folder:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File ".\deploy.ps1"
   ```

3. Confirm the auto-detected install directory. If detection fails, enter the path containing `vmware.exe`.
4. Choose a package. The compatible one is marked as recommended.
5. Choose whether to replace `vmware-tray.exe` (default: yes for the full package, no for the official 17 package).
6. Approve the UAC prompt. The elevated child process performs the file operations.

The script:

- writes `vmui-zh_CN.dll`, `vmappsdk-zh_CN.dll`, and `vmware.vmsg` to `<install>\messages\zh_CN`;
- optionally replaces `<install>\vmware-tray.exe` when the architecture matches;
- sets `pref.locale = "zh_CN"` in `%APPDATA%\VMware\preferences.ini`;
- backs up every file it overwrites under `backup\<timestamp>\` with a `manifest.json` and `deploy.log`.

Roll back automatically if a write fails after modifications begin.

## Restore

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\restore.ps1"
```

Choose a backup (latest by default). The script restores overwritten files, removes files that did not exist before deployment, restores the tray if it was replaced, and puts `pref.locale` back to its previous state (or removes the line). UAC is required.

Backups remain in `backup\`. To restore a backup manually, copy files from its `files\` directory and inspect `manifest.json`.

## Notes

- Program Files changes require administrator rights; both scripts self-elevate via `Start-Process -Verb RunAs`.
- Resource DLLs and the patched tray are unsigned because resources were transplanted. Antivirus or SmartScreen may flag them; this is expected.
- An existing `messages\zh_CN` directory is overwritten and backed up. On a clean English install, restore removes it.
- The 17 and 26 packages are not interchangeable: 17 uses x86 binaries, 26H1u1 uses x64 binaries.
- Upgrade VMware before redeploying. If an upgrade leaves stale language files, restore first or reinstall the application.
- Scripts target Windows PowerShell 5.1 and are stored as UTF-8 with BOM.
- Tested on Windows 10.0.26100 x64 with VMware Workstation 26H1u1 (26.0.1 build 25688693).
