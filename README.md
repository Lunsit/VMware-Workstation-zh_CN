# VMware Workstation 简体中文汉化包

为本地 VMware Workstation 部署简体中文资源，支持自动备份与一键恢复。部署和恢复均自动申请管理员权限。

## 目录结构

```
VMware-Workstation-zh_CN/
  17-official-zh_CN/   官方 17.6.4 简体中文资源（x86）+ 官方托盘程序
  full-zh_CN/          26H1u1 完整汉化（x64）+ 已汉化托盘程序
  deploy.ps1           自动检测安装目录、选择汉化包和托盘、申请授权并部署
  restore.ps1          选择备份并恢复到部署前的状态
  README.md
```

## 兼容性

| 汉化包 | 适用版本 | 架构 | 托盘程序 |
| --- | --- | --- | --- |
| `17-official-zh_CN` | VMware Workstation 17.x | x86 | 官方 17.6.4 托盘，可选替换 |
| `full-zh_CN` | VMware Workstation 26.x（已验证 26H1u1 / 26.0.1 build 25688693） | x64 | 已汉化的 26H1u1 托盘，可选替换 |

`deploy.ps1` 会读取已安装的 `vmware.exe` 与汉化包中 `vmui-zh_CN.dll` 的 PE 架构，架构不一致时拒绝部署。主版本号不一致时需要手动确认；完整汉化包面向 26.x。

## 使用方法

1. 关闭 VMware Workstation 及所有虚拟机。
2. 在本目录中打开 PowerShell 并运行：

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File ".\deploy.ps1"
   ```

3. 确认自动检测到的安装目录。若检测失败，请手动输入包含 `vmware.exe` 的目录。
4. 选择汉化包，兼容的包会标注“推荐”。
5. 选择是否替换 `vmware-tray.exe`（完整汉化包默认替换，官方 17 包默认不替换）。
6. 在 UAC 窗口中点击“是”，随后由提权子进程完成文件操作。

脚本会：

- 将 `vmui-zh_CN.dll`、`vmappsdk-zh_CN.dll` 和 `vmware.vmsg` 写入 `<安装目录>\messages\zh_CN`；
- 在架构匹配时可选替换 `<安装目录>\vmware-tray.exe`；
- 在 `%APPDATA%\VMware\preferences.ini` 中设置 `pref.locale = "zh_CN"`，使中文成为默认启动语言；
- 将每个被覆盖的文件备份到 `backup\<时间戳>\`，并生成 `manifest.json` 和 `deploy.log`。

若在开始修改文件之后发生错误，脚本会自动回滚。

## 恢复

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ".\restore.ps1"
```

选择要恢复的备份（默认最新）。脚本会还原被覆盖的文件，删除部署时新增的文件，恢复被替换的托盘程序，并将 `pref.locale` 恢复为原值（原来不存在则删除该行）。恢复同样需要管理员权限。

备份保留在 `backup\` 中。如需手动恢复，可从备份的 `files\` 目录复制文件，具体记录见 `manifest.json`。

## 注意事项

- 修改 Program Files 需要管理员权限，两个脚本均通过 `Start-Process -Verb RunAs` 自动提权。
- 资源 DLL 和替换后的托盘程序因资源移植而不再具有有效签名，杀毒软件或 SmartScreen 可能提示风险，属正常现象。
- 已存在的 `messages\zh_CN` 目录会被覆盖并备份；在原本为英文的干净安装上，恢复时该目录会被删除。
- 17 与 26 的汉化包不可混用：17 为 x86 二进制，26H1u1 为 x64 二进制。
- 升级 VMware 后如需重新部署，请先恢复或重装应用，避免残留旧版本语言文件。
- 脚本适用于 Windows PowerShell 5.1，以 UTF-8（带 BOM）保存。
- 已在 Windows 11（build 26100）x64、VMware Workstation 26H1u1（26.0.1 build 25688693）上测试。

## 免责声明

汉化资源提取或改编自 VMware Workstation 安装程序，版权归 VMware 所有。请在拥有合法授权的本地 VMware Workstation 上使用。本项目与 Broadcom、VMware 无关。
