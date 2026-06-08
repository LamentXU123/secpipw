<p align="center">
  <img src="doc/assets/logo.png" alt="secpipw logo" width="160">
</p>

[English](./README.md) | 简体中文

[![Test](https://github.com/LamentXU123/spip/actions/workflows/test.yml/badge.svg)](https://github.com/LamentXU123/spip/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python_version](https://img.shields.io/pypi/pyversions/secpipw.svg?logo=python&logoColor=FBE071)
![PyPI Version](https://img.shields.io/pypi/v/secpipw)
[![Codecov](https://codecov.io/gh/LamentXU123/spip/graph/badge.svg)](https://codecov.io/gh/LamentXU123/spip)

一个开源、免费、强大且轻量的 pip 防护工具，用于帮助你避免供应链攻击。

使用它之后，你不会仅仅因为输入了 `pip install`，就被被污染的 LiteLLM 等类似事件坑到。

虽然 `secpipw` 的设计目标是降低学习成本，但在生产环境中使用本产品之前，我们仍然建议你阅读我们的[文档](https://spip.lamentxu.top/docs)。

## 这是什么？

目前，供应链攻击是全球范围内主要的安全问题之一。`secpipw` 项目是一个面向未来的 `pip` 包装器，专注于供应链风险控制。

## 等等，具体是什么意思？

你可以使用：

```bash
spip install requests
```

而不是：

```bash
pip install requests
```

从供应链安全角度看，这样安装软件包会更安全。

你不需要配置，不需要学习，只需要像平常一样安装即可。

换句话说，你可以用 `spip install` 完全替代 `pip install`，让安装过程更安全 :)

## 包管理器支持

secpipw 现在支持更多样化的包管理器场景：

- [x] `pip`：`spip install requests`
- [x] `pipx`：`spipx install black`
- [x] `poetry`：`spoetry add requests`
- [x] `uv`：`suv pip install requests`
- [ ] `conda`：计划中

你可以保护常见的 `pipx`、`poetry` 和 `uv` 加包操作：

```bash
spipx install black
spoetry add requests
suv pip install requests
```

本包会安装 `spipx`、`spoetry` 和 `suv` 这几个专用入口。当前受保护的命令包括 `pipx install`、`pipx inject`、
`pipx run`、`poetry add`、`poetry self add`、`uv pip install`、`uv add`、
`uv tool install` 和 `uv tool run`。其它非安装命令会保持原样透传。对于会安装
软件包但无法准确转换成 pip 安装计划的命令，例如 `pipx upgrade`、
`poetry add --source internal ...` 或 `uv run ...`，spip 会拒绝执行，而不是在
没有检查的情况下继续安装。

如果你想获得接近无感替换的体验，可以设置一个从 `pip` 到 `spip` 的 shell 别名。

命令提示符（Windows）：

```cmd
pip install secpipw
doskey pip=spip $*
```

Bash（Linux）：

```bash
pip install secpipw
echo "alias pip='spip'" >> ~/.bashrc
source ~/.bashrc
```

Zsh（macOS）：

```zsh
pip install secpipw
echo "alias pip='spip'" >> ~/.zshrc
source ~/.zshrc
```

当你输入 `spip install` 时，`secpipw` 项目会主动检查所有供应链风险，并避免你安装潜在恶意软件包。

对于 `install`，`secpipw` 使用 pip 自身的解析器，然后在 pip 构建或安装已解析的发行包之前检查选中的安装计划。如果检查通过，同一个 pip 安装流程会继续执行；`secpipw` 不会针对已经解析的软件包再运行第二次 `pip install`。

除 `install` 命令外，本项目的行为与原始 `pip` 程序完全一致。也就是说，你在任何情况下都可以使用 `spip` 替代 `pip` :)

对于 `pipx`、`poetry` 和 `uv`，secpipw 会先运行一次 pip 兼容的预解析和安装产物检查，然后再把控制权交给原始工具。实际环境更新仍然由原工具完成。

更多细节请参阅我们的文档：https://spip.lamentxu.top/docs

## secpipw 解决了什么问题？

供应链投毒一直是一个长期存在的安全问题。现有解决方案包括 GuardDog 这类成熟但运行成本较高的工具，也包括 sfw 这类完全依赖付费 Socket API 的轻量工具。GuardDog 对日常 CI 使用来说太重，更适合安全研究人员进行静态分析。如果对 `pip install` 下载的每个产物，包括所有依赖，都运行 GuardDog，安装过程会变慢。sfw 更轻量，但它依赖付费 API，会给日常开发者带来额外成本。

secpipw 通过接入 pip 的安装器，并将安全检查直接合并到 pip install 的下载与安装流程中来解决这个问题。同时，它通常只会带来很小的性能影响。secpipw 对所有人完全免费。

如今，许多独立开发者都遭遇过 CI 服务器被入侵，导致密钥泄露并造成严重损失。安装 secpipw 后，这类风险会大幅降低，并且不需要付费、不需要额外性能预算，也不需要学习或配置。只需用 `pip install secpipw` 安装一次，再设置一次别名，就可以继续使用 pip，同时在后台获得一层重要保护。

## 警告策略

## TODO

欢迎贡献：

- 框架
    - [x] 支持受保护的 `uv pip install`、`uv add`、`uv tool install` 和 `uv tool run`
    - [x] 支持受保护的 `pipx install`、`pipx inject` 和 `pipx run`
    - [x] 支持受保护的 `poetry add` 和 `poetry self add`
    - [ ] 支持 `conda`
- CI
    - [x] 在 GitHub workflow 中编写基准测试 CI，用于比较 `spip install` 和 `pip install` 的性能
- 文档
    - [ ] 使用现代文档框架重构 `/doc/docs` 目录
    - [ ] 支持网站在手机端浏览。@didongji91
- 检查
    - [x] 在多次 `spip` 安装之间记录并比较已安装软件包的 entry-point 和 `.pth` 基线
        - [x] 是否新增了新的或发生变化的 `.pth` 文件
        - [x] entry-point 元数据或脚本文件是否发生变化
    - [x] 从 pip 解析后的安装报告中检测 yanked release
    - [x] 在已有 PyPI release 元数据可用时比较归档 hash
    - [ ] 增加待安装版本与软件包上一版本之间的差异检查，搜索恶意变更
        - [ ] setup.py 是否发生变化

我们目前有三种安装警告策略：

- `HIGH`：暂停安装，并要求使用 `--spip-ignore-warning`
- `MEDIUM`：继续前提示 `y/n`
- `LOW`：发出警告并继续

默认敏感度是 `low`，会使用上述策略。你可以通过 `--sensitivity medium` 或 `--sensitivity high` 让门禁更严格：

- `--sensitivity medium`：`MEDIUM` 及以上级别会暂停安装；`LOW` 会提示确认。
- `--sensitivity high`：`LOW` 及以上级别都会暂停安装。

使用 `--spip-ignore <level>` 可以完全忽略该严重程度及以下的 warning。例如，
`--spip-ignore LOW` 会忽略 `LOW` warning，`--spip-ignore MEDIUM` 会同时忽略 `LOW`
和 `MEDIUM` warning。被忽略的 warning 不会输出，只可能产生被忽略级别
warning 的检查项也会被跳过。

## 缓存

默认情况下，secpipw 会将 PyPI 名称、发布时间和维护者邮箱历史缓存存储在用户缓存目录中，因此同一份缓存可以在多个项目之间复用。设置 `SPIP_CACHE_DIR` 可以覆盖缓存目录。

## Benchmark

运行本地基准测试：

```bash
python scripts/benchmark_install.py --runs 5 --warmups 0
```

文档页使用的 package-manager benchmark 可以这样运行：

```bash
python scripts/benchmark_package_managers.py --runs 10
```

默认 install benchmark 会比较 `pip install requests` 和
`spip install requests`，下载和安装全过程都会计时。它会使用本地
wheelhouse、`--no-index`、`--no-deps`，以及每次测量新建的 `--target`
目录，因此结果聚焦在对同一个有名包本体的多次安装，而不是依赖树。另有一组
package-manager benchmark 会记录受保护的 `uv`、`pipx` 和 `poetry`
路由启动/预检查开销，只在 docs 页面展示。Benchmark GitHub Actions
workflow 会在 `main` 的相关变更、每周定时任务或手动触发时运行。它会把最新
`benchmark.json` 和 `manager-benchmark.json` 发布到远端
`benchmark-data` 分支。benchmark 更新不会推进 `main`。

当 `secpipw` 检测到潜在风险时，会根据风险严重程度发出对应级别的警告。

目前，本项目有几个主要检查点：

- [x] 伪拼写错误检查：攻击者经常使用“伪拼写错误”将恶意依赖包注入被污染的源文件。`secpipw` 会先解析 `pip install` 将要下载的所有软件包，然后将解析出的非热门软件包名称与本地热门软件包列表进行比较。警告级别：
    - 中等严重性：`requsets` vs `requests`
    - 中等严重性：`panda` vs `pandas`
    - 低严重性：`sixth` vs `six`
- [x] 直接 URL 依赖检查：如果安装目标或已解析依赖使用直接 URL、VCS URL 或 PEP 508 直接引用，`secpipw` 会发出 `MEDIUM` 警告。
- [x] 新发布版本检查：如果选中的 PyPI 版本发布时间少于 8 小时，`secpipw` 会发出 `MEDIUM` 警告；如果发布时间少于 48 小时，`secpipw` 会发出 `LOW` 警告。
- [x] Yanked release 检查：如果 pip 解析出的版本已经被标记为 yanked，`secpipw` 会基于 pip install report 发出 `MEDIUM` 警告。
- [x] 归档 hash 检查：如果 PyPI release 元数据已经可用，并且选中 wheel/sdist 的 digest 与解析出的归档 hash 不一致，`secpipw` 会发出 `HIGH` 警告。
- [x] 空描述检查：如果选中的 PyPI 版本元数据没有 summary，也没有 long description，`secpipw` 会发出 `LOW` 警告。
- [x] 可疑元数据 URL 检查：如果 PyPI 元数据指向短链接、原始 IP、嵌入式凭据或类似可疑 URL，`secpipw` 会发出 `LOW` 警告。
- [x] 仓库不匹配检查：如果 PyPI 元数据指向一个 GitHub/GitLab 仓库，但仓库名称看起来与软件包名称无关，`secpipw` 会发出 `LOW` 警告。
- [x] 维护者邮箱域名漂移检查：如果某个软件包的维护者邮箱域名与本地 `secpipw` 历史缓存相比发生变化，`secpipw` 会发出 `LOW` 警告。
- [x] 零版本检查：如果选中的软件包版本是 `0.0` 或 `0.0.0`，`secpipw` 会发出 `LOW` 警告。
- [x] `.pth` 文件检测：现在大多数攻击者不会直接在软件包内注入恶意代码，而是会把恶意内容放在以 `import` 开头的 `.pth` 文件中。`secpipw` 只会在安装后检查已安装文件系统的差异。警告级别始终为 `MEDIUM`，并且 `secpipw` 会询问是否删除已安装的可疑 `.pth` 文件。
- [ ] TODO ...
