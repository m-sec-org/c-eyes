# GitHub `c-eyes` 源码自助打包说明

这份文档说明当前 `c-eyes` 源码树怎么直接打包。

## 当前验证状态

当前这份 `c-eyes` 源码树已经做过实际构建验证：

- Windows 实测打包成功
- Linux 通过 WSL 实测打包成功

并且两个平台生成的产物都已经通过 `-h` 启动自检。

## 当前源码树里已经包含什么

当前 `c-eyes/third_party/` 已经包含：

- `windows-toolchain`
- `yara-x-dist-windows`
- `yara-x-dist-linux-glibc-2.28`

所以现在拿到这份 `c-eyes` 源码后，主要不再缺打包所需的 YARA-X 原生产物和项目内置 Windows 工具链。

## 你还需要准备什么

### Windows

- Windows `amd64`
- Go `1.25.0` 或更高版本
- PowerShell

### Linux

- Linux `amd64`
- Go `1.25.0` 或更高版本
- `bash`
- `gcc`
- `pkg-config`

如果 Linux 的 `third_party/yara-x-dist-linux-glibc-2.28` 被删除或损坏，打包现在会直接失败。

当前这条标准打包路径：

- 不回退到其他 Linux YARA 目录
- 不回退到现场 Rust 重建

## Windows 打包

### 先进入源码目录

```powershell
cd c-eyes
```

### 检查关键路径

- `third_party/yara-x-dist-windows/include`
- `third_party/yara-x-dist-windows/lib`
- `third_party/yara-x-dist-windows/bin`
- `third_party/windows-toolchain/mingw64/bin/gcc.exe`

### 执行打包脚本

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-windows.ps1
```

### 构建成功后看哪里

- `dist-windows-amd64/c-eyes.exe`

### 自检

```powershell
.\dist-windows-amd64\c-eyes.exe -h
```

## Linux 打包

### 先进入源码目录

```bash
cd c-eyes
```

### 检查关键路径

- `third_party/yara-x-dist-linux-glibc-2.28/include`
- `third_party/yara-x-dist-linux-glibc-2.28/lib` 或 `lib64`

### 执行打包脚本

```bash
TARGET_ARCH=amd64 bash ./scripts/build-linux.sh dist-linux-amd64
```

```bash
TARGET_ARCH=arm64 bash ./scripts/build-linux.sh dist-linux-arm64
```

### 构建成功后看哪里

- `dist-linux-amd64/c-eyes`
- 或 `dist-linux-arm64/c-eyes`

### 自检

```bash
./dist-linux-amd64/c-eyes -h
```

### 依赖与失败策略

- Linux 打包固定使用 `glibc 2.28` 依赖树：`third_party/yara-x-dist-linux-glibc-2.28-<arch>`。
- 若主机 `glibc` 低于 `2.28`，脚本会直接失败，不做自适应回退。
- 依赖获取优先级：
  - 先使用当前路径下本地 `c-eyes-third-party` bundle。
  - 本地 bundle 不可用时，再按 `third_party/repo.txt` 与 `third_party/version.txt` 自动从 release 下载。
- 如需走代理下载，可设置 `THIRD_PARTY_PROXY=http://127.0.0.1:7890`。

## 当前正确的理解

现在更准确的说法是：

- 这份 `c-eyes` 源码树已经带了打包所需的 `third_party/`
- Windows 打包已经实测通过
- Linux 打包已经通过 WSL 实测通过
- Linux 机器本身仍需安装 `Go`、`gcc`、`pkg-config`

## 你可以直接发给别人的简短版本

如果你要发一句话给别人，可以直接用这段：

“进入 `c-eyes` 目录后，Windows 执行 `powershell -ExecutionPolicy Bypass -File .\\scripts\\build-windows.ps1`，Linux 执行 `bash ./scripts/build-linux.sh`。这份源码已经带了 `third_party/` 原生依赖，并且 Windows 和 WSL Linux 都已实测打包通过；Linux 机器本身仍需安装 Go、gcc、pkg-config，打包后再用 `-h` 做一次自检。”
