# secured_pip 中文文档

[English](./README.md) | 简体中文

仍在开发中，欢迎贡献。项目站点：https://spip.lamentxu.top/

## secured_pip

`secured_pip` 是一个开源、免费、轻量且功能较强的 `pip` 防护工具，主要用于帮助用户避免 Python 包供应链攻击。

使用它之后，你不会只是因为敲了一条 `pip install`，就被被投毒的包坑到，例如之前类似 LiteLLM 投毒这类供应链安全问题。

虽然 `secured_pip` 的设计目标是降低学习成本，但在生产环境中使用之前，仍然建议先阅读项目文档。

## 这是什么？

当前，供应链攻击已经成为全球范围内的重要安全问题之一。`secured_pip` 是一个面向供应链风险控制的 `pip` 包装器。

## 等等，所以它到底怎么用？

你可以使用：

```bash
spip install requests
```

替代：

```bash
pip install requests
```

这样可以在供应链安全层面更安全地安装 Python 包。

你不需要复杂配置，也不需要额外学习。它的目标就是尽量做到安装后即可上手。

换句话说，你可以在大多数情况下直接用 `spip install` 替代 `pip install`，让安装过程更安全。

如果你想获得接近无感的使用体验，也可以把 `pip` 设置为 `spip` 的命令别名。

### Command Prompt（Windows）

```bat
pip install secured_pip
doskey pip=spip $*
```

### Bash（Linux）

```bash
pip install secured_pip
echo "alias pip='spip'" >> ~/.bashrc
source ~/.bashrc
```

### Zsh（macOS）

```bash
pip install secured_pip
echo "alias pip='spip'" >> ~/.zshrc
source ~/.zshrc
```

当你输入 `spip install` 时，`secured_pip` 会主动检查供应链相关风险，尽量避免你安装潜在恶意包。

对于安装命令，`secured_pip` 会使用 `pip` 自身的依赖解析器，然后在 `pip` 构建或安装解析出的发行包之前，检查本次选中的安装计划。如果检查通过，后续会继续执行同一套 `pip install` 流程；`secured_pip` 不会对已经解析好的包再次执行第二次 `pip install`。

除了安装相关命令外，本项目的行为会尽量与原始 `pip` 保持一致。也就是说，在大多数情况下，你都可以使用 `spip` 替代 `pip`。

更多细节请查看项目文档：https://spip.lamentxu.top/docs

## secured_pip 解决了什么问题？

供应链投毒一直是一个长期存在的安全问题。现有方案中，有一些成熟但运行成本较高的工具，例如 GuardDog；也有一些较轻量的工具，例如 sfw，但它完全依赖付费的 Socket API。

GuardDog 对日常 CI 使用来说偏重，更适合安全研究人员做静态分析。如果每次执行 `pip install` 时都对下载的所有构件和依赖运行 GuardDog，安装速度会受到较大影响。

sfw 虽然更轻量，但它依赖付费 API，这会给日常开发者带来额外成本。

`secured_pip` 的做法是挂接到 `pip` 的安装器中，把安全检查合并到 `pip install` 的下载和安装流程里。与此同时，它通常只会带来较小的性能影响，并且对所有人完全免费。

现在，很多独立开发者都曾因为 CI 服务器被入侵而泄露密钥，进而造成严重损失。安装 `secured_pip` 后，这类风险可以得到一定程度的降低，而且不需要付费、不需要额外性能预算，也不需要复杂学习和配置。只需要执行一次：

```bash
pip install secured_pip
```

再设置一次别名，就可以继续按照原来的 `pip` 使用习惯工作，同时在后台获得一层重要的安全防护。

## 警告策略

TODO

## 欢迎贡献

### Framework

* 支持 `uv`
* 支持 `pipx`
* 支持 `conda`

### CI

* 在 GitHub Workflow 中编写 benchmark CI，用于比较 `spip install` 和 `pip install` 的性能差异

### Documentation

* 使用更现代的文档框架重构 `/doc/docs` 目录
* 支持移动端网站浏览

### Checks

* 记录并比较多次 `spip` 安装过程中的 entry-point 和 `.pth` 基线
* 检查是否新增或修改了 `.pth` 文件
* 检查 entry-point 元数据或脚本文件是否发生变化
* 检查当前待安装版本与上一版本之间的差异，搜索可能的恶意变更
* 检查 `setup.py` 是否发生变化

## 当前安装警告策略

目前项目中有三种安装警告策略：

* `HIGH`：暂停安装，需要添加 `--ignore-warning` 才能继续
* `MEDIUM`：继续前提示用户输入 `y/n` 进行确认
* `LOW`：输出警告并继续安装

默认敏感度为 `low`，对应上面的策略。你也可以使用 `--sensitivity medium` 或 `--sensitivity high` 让检查门槛更严格：

* `--sensitivity medium`：`MEDIUM` 及以上级别会暂停安装；`LOW` 级别会提示确认
* `--sensitivity high`：`LOW` 及以上级别都会暂停安装

## 缓存

`secured_pip` 默认会把 PyPI 包名、发布时间和维护者邮箱历史记录缓存到用户缓存目录中，因此同一份缓存可以在不同项目之间复用。

如果需要修改缓存目录，可以设置 `SPIP_CACHE_DIR` 环境变量。

当 `secured_pip` 检测到潜在风险时，会根据风险严重程度抛出对应等级的警告。

## 当前主要检查点

目前项目包含以下几个主要检查点。

### 1. 拼写仿冒检查

攻击者经常使用“拼写仿冒”的方式，把恶意依赖包注入到被投毒的源文件中。

`secured_pip` 会先解析出 `pip install` 即将下载的所有包，然后将其中不够热门的包名与本地热门包列表进行比较，从而发现可疑包名。

警告等级示例：

* `requsets` 与 `requests`：中危
* `panda` 与 `pandas`：中危
* `sixth` 与 `six`：低危

### 2. Direct URL 依赖检查

如果安装目标或解析出的依赖使用了 Direct URL、VCS URL 或 PEP 508 direct reference，`secured_pip` 会抛出 `MEDIUM` 警告。

### 3. 新发布版本检查

如果选中的 PyPI 版本发布时间距离当前时间不到 8 小时，`secured_pip` 会抛出 `MEDIUM` 警告。

如果发布时间不到 48 小时，`secured_pip` 会抛出 `LOW` 警告。

### 4. 空描述检查

如果选中的 PyPI 版本元数据中没有 summary，也没有 long description，`secured_pip` 会抛出 `LOW` 警告。

### 5. 可疑元数据 URL 检查

如果 PyPI 元数据指向短链接、裸 IP、可疑顶级域名、带嵌入式凭据的链接，或其他类似可疑 URL，`secured_pip` 会抛出 `LOW` 警告。

### 6. 仓库名称不匹配检查

如果 PyPI 元数据指向 GitHub 或 GitLab 仓库，但仓库名称与包名看起来不相关，`secured_pip` 会抛出 `LOW` 警告。

### 7. 维护者邮箱域名漂移检查

如果某个包的维护者邮箱域名与本地 `secured_pip` 历史缓存相比发生变化，`secured_pip` 会抛出 `LOW` 警告。

### 8. 零版本检查

如果选中的包版本是 `0.0` 或 `0.0.0`，`secured_pip` 会抛出 `LOW` 警告。

### 9. `.pth` 文件检测

现在有些攻击者不会直接把恶意代码写进包的主要代码里，而是把恶意逻辑放在 `.pth` 文件中，并以 `import` 语句开头。

`secured_pip` 会在安装后检查文件系统差异，检测是否出现可疑的 `.pth` 文件。这个检查的警告等级始终为 `MEDIUM`，并且 `secured_pip` 会询问用户是否删除这个可疑的已安装 `.pth` 文件。

## TODO

更多功能仍在开发中。
