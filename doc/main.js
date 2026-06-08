const root = document.documentElement

window.addEventListener('focus', () => {
  root.classList.remove('app-paused')
})

window.addEventListener('blur', () => {
  root.classList.add('app-paused')
})

const sleep = (ms) => new Promise((resolve) => window.setTimeout(resolve, ms))

const scenes = document.querySelectorAll('[data-command-scene]')
const copyButtons = document.querySelectorAll('[data-copy-target]')
const scrollButtons = document.querySelectorAll('[data-command-scroll]')
const installButtons = document.querySelectorAll('[data-scroll-install]')
const nextButtons = document.querySelectorAll('[data-scroll-next]')
const topButtons = document.querySelectorAll('[data-scroll-top]')
const animatedCharts = document.querySelectorAll('[data-chart-animate]')
const languageSwitches = document.querySelectorAll('[data-language-switch]')
const docTabGroups = document.querySelectorAll('[data-doc-tabs]')
const docsSearchTriggers = document.querySelectorAll('.docs-search')
const docsSearchModal = document.querySelector('[data-docs-search-modal]')
const docsSearchInput = document.querySelector('[data-docs-search-input]')
const docsSearchResults = document.querySelector('[data-docs-search-results]')
const benchmarkRatioNodes = document.querySelectorAll('[data-benchmark-ratio]')
const benchmarkPipMedianNodes = document.querySelectorAll('[data-benchmark-pip-median]')
const benchmarkSpipMedianNodes = document.querySelectorAll('[data-benchmark-spip-median]')
const benchmarkRunsNodes = document.querySelectorAll('[data-benchmark-runs]')
const benchmarkGeneratedNodes = document.querySelectorAll('[data-benchmark-generated]')
const benchmarkTableBodies = document.querySelectorAll('[data-benchmark-table]')
const combinedBenchmarkTableBodies = document.querySelectorAll('[data-benchmark-combined-table]')
const benchmarkSourceLinks = document.querySelectorAll('[data-benchmark-source-link]')
const benchmarkSources = [
  'https://raw.githubusercontent.com/LamentXU123/secpipw/benchmark-data/benchmark.json',
  'https://raw.githubusercontent.com/LamentXU123/spip/benchmark-data/benchmark.json',
  '/benchmark.json',
]
const managerBenchmarkSources = [
  'https://raw.githubusercontent.com/LamentXU123/secpipw/benchmark-data/manager-benchmark.json',
  'https://raw.githubusercontent.com/LamentXU123/spip/benchmark-data/manager-benchmark.json',
  '/manager-benchmark.json',
]

const setNodeText = (nodes, value) => {
  for (const node of nodes) {
    node.textContent = value
  }
}

const finiteNumber = (value) => {
  const number = Number(value)
  return Number.isFinite(number) ? number : null
}

const formatSeconds = (value) => {
  const number = finiteNumber(value)
  return number === null ? '--' : `${number.toFixed(4)}s`
}

const formatBenchmarkRatio = (payload) => {
  const label = payload?.summary?.ratio?.avg_label
  if (typeof label === 'string' && label.startsWith('x')) {
    return label
  }

  const explicit = finiteNumber(payload?.summary?.ratio?.avg)
  if (explicit !== null) {
    return `x${explicit.toFixed(4)}`
  }

  const pipAvg = finiteNumber(payload?.summary?.pip?.avg)
  const spipAvg = finiteNumber(payload?.summary?.spip?.avg)
  if (pipAvg !== null && pipAvg > 0 && spipAvg !== null) {
    return `x${(spipAvg / pipAvg).toFixed(4)}`
  }

  return 'x--'
}

const formatBenchmarkDate = (value) => {
  const date = new Date(value)
  return Number.isNaN(date.getTime())
    ? '--'
    : `${date.toISOString().replace('T', ' ').slice(0, 16)} UTC`
}

const benchmarkSourceUrl = (payload) => {
  const candidates = [
    payload?.benchmark_url,
    payload?.source?.job_url,
    payload?.source?.run_url,
  ]
  for (const value of candidates) {
    if (typeof value !== 'string') {
      continue
    }
    try {
      const url = new URL(value)
      if (url.protocol === 'https:' && url.hostname === 'github.com') {
        return url.href
      }
    } catch {
      // Ignore malformed benchmark source URLs from stale payloads.
    }
  }
  return undefined
}

const formatPercent = (value) => {
  const number = finiteNumber(value)
  return number === null ? '--' : `${number >= 0 ? '+' : ''}${number.toFixed(2)}%`
}

const formatSignedSeconds = (value) => {
  const number = finiteNumber(value)
  return number === null ? '--' : `${number >= 0 ? '+' : ''}${number.toFixed(4)}s`
}

const benchmarkRows = (payload) => {
  const scenarios = Array.isArray(payload?.scenarios) ? payload.scenarios : []
  if (scenarios.length > 0) {
    return scenarios
  }

  return payload?.summary
    ? [
        {
          key: 'spip-default',
          label: 'spip',
          ...payload.summary,
        },
      ]
    : []
}

const benchmarkModeLabel = (scenario) => {
  return scenario?.requirement || scenario?.label || '--'
}

const renderBenchmarkTables = (payload) => {
  const rows = benchmarkRows(payload)
  for (const body of benchmarkTableBodies) {
    body.innerHTML = rows
      .map((scenario) => {
        const overhead = scenario?.overhead || {}
        const overheadLabel = `${formatSignedSeconds(
          overhead.avg_seconds
        )} (${formatPercent(overhead.avg_percent)})`
        return `
          <tr>
            <td>${escapeHtml(benchmarkModeLabel(scenario))}</td>
            <td><code>${escapeHtml(formatSeconds(scenario?.pip?.avg))}</code></td>
            <td><code>${escapeHtml(formatSeconds(scenario?.spip?.avg))}</code></td>
            <td><code>${escapeHtml(
              scenario?.ratio?.avg_label || formatBenchmarkRatio({ summary: scenario })
            )}</code></td>
            <td><code>${escapeHtml(overheadLabel)}</code></td>
          </tr>
        `
      })
      .join('')
  }
}

const benchmarkCombinedRows = (managerPayload) => {
  const rows = Array.isArray(managerPayload?.summaries)
    ? managerPayload.summaries.map((summary) => ({
        wrapper: summary?.wrapper || '--',
        guardedEntry: summary?.guarded_entry || '--',
        packages: Array.isArray(summary?.packages) ? summary.packages.join(', ') : '--',
        originalAvg: finiteNumber(summary?.original?.avg),
        guardedAvg: finiteNumber(summary?.guarded?.avg),
        ratio: summary?.ratio?.avg_label || 'x--',
      }))
    : []
  const routeOrder = { pip: 0, uv: 1, pipx: 2, poetry: 3 }
  return rows.sort(
    (left, right) => (routeOrder[left.wrapper] ?? 99) - (routeOrder[right.wrapper] ?? 99),
  )
}

const renderCombinedBenchmarkTables = (managerPayload) => {
  const rows = benchmarkCombinedRows(managerPayload)
  for (const body of combinedBenchmarkTableBodies) {
    body.innerHTML = rows
      .map(
        (scenario) => `
          <tr>
            <td>${escapeHtml(scenario?.wrapper || '--')}</td>
            <td>${escapeHtml(scenario?.guardedEntry || '--')}</td>
            <td>${escapeHtml(scenario?.packages || '--')}</td>
            <td><code>${escapeHtml(formatSeconds(scenario?.originalAvg))}</code></td>
            <td><code>${escapeHtml(formatSeconds(scenario?.guardedAvg))}</code></td>
            <td><code>${escapeHtml(scenario?.ratio || 'x--')}</code></td>
          </tr>
        `,
      )
      .join('')
  }
}

const updateBenchmarkSourceLinks = (payload) => {
  const url = benchmarkSourceUrl(payload)
  if (!url) {
    return
  }

  for (const link of benchmarkSourceLinks) {
    link.href = url
  }
}

const loadBenchmarkPayload = async () => {
  for (const source of benchmarkSources) {
    try {
      const url = source.startsWith('http')
        ? `${source}?t=${Date.now()}`
        : source
      const response = await fetch(url, { cache: 'no-store' })
      if (response.ok) {
        return response.json()
      }
    } catch {
      // Try the next benchmark source.
    }
  }
  return null
}

const loadManagerBenchmarkPayload = async () => {
  for (const source of managerBenchmarkSources) {
    try {
      const url = source.startsWith('http')
        ? `${source}?t=${Date.now()}`
        : source
      const response = await fetch(url, { cache: 'no-store' })
      if (response.ok) {
        return response.json()
      }
    } catch {
      // Try the next benchmark source.
    }
  }
  return null
}

const loadBenchmark = async () => {
  const hasBenchmarkNodes =
    benchmarkRatioNodes.length > 0 ||
    benchmarkPipMedianNodes.length > 0 ||
    benchmarkSpipMedianNodes.length > 0 ||
    benchmarkRunsNodes.length > 0 ||
    benchmarkGeneratedNodes.length > 0 ||
    benchmarkTableBodies.length > 0 ||
    combinedBenchmarkTableBodies.length > 0

  if (!hasBenchmarkNodes) {
    return
  }

  const payload = await loadBenchmarkPayload()
  if (!payload) {
    return
  }

  setNodeText(benchmarkRatioNodes, formatBenchmarkRatio(payload))
  setNodeText(benchmarkPipMedianNodes, formatSeconds(payload?.summary?.pip?.avg))
  setNodeText(benchmarkSpipMedianNodes, formatSeconds(payload?.summary?.spip?.avg))
  setNodeText(benchmarkRunsNodes, String(payload?.runs ?? '--'))
  setNodeText(benchmarkGeneratedNodes, formatBenchmarkDate(payload?.generated_at))
  updateBenchmarkSourceLinks(payload)
  renderBenchmarkTables(payload)

  if (combinedBenchmarkTableBodies.length > 0) {
    const managerPayload = await loadManagerBenchmarkPayload()
    if (managerPayload) {
      setNodeText(benchmarkRunsNodes, String(managerPayload?.runs ?? '--'))
      setNodeText(benchmarkGeneratedNodes, formatBenchmarkDate(managerPayload?.generated_at))
      updateBenchmarkSourceLinks(managerPayload)
    }
    renderCombinedBenchmarkTables(managerPayload)
  }
}

loadBenchmark()

if (scenes.length > 0) {
  if ('scrollRestoration' in history) {
    history.scrollRestoration = 'manual'
  }
  window.scrollTo(0, 0)
  window.addEventListener('pageshow', () => {
    window.scrollTo(0, 0)
  })
}

const escapeHtml = (value) =>
  value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')

const renderCommand = (text) => {
  const firstSpace = text.indexOf(' ')
  if (firstSpace === -1) {
    return renderCommandBinary(text)
  }

  const command = text.slice(0, firstSpace)
  const rest = text.slice(firstSpace)
  return `${renderCommandBinary(command)}<span class="command-rest">${escapeHtml(rest)}</span>`
}

const renderCommandBinary = (command) => {
  const normalized = command.trim().toLowerCase()
  let className = 'command-bin'
  if (normalized === 'pip') {
    className += ' command-bin-pip'
  } else if (normalized === 'spip') {
    className += ' command-bin-spip'
  }
  return `<span class="${className}">${escapeHtml(command)}</span>`
}

const runScene = async (scene) => {
  const commandText = scene.querySelector('[data-command-text]')
  const measure = scene.querySelector('[data-command-measure]')
  const caret = scene.querySelector('[data-command-caret]')
  const copy = scene.querySelector('[data-command-copy]')
  const message = scene.querySelector('[data-command-message]')
  const scrollCue = scene.querySelector('[data-command-scroll]')
  const terminalWindow = scene.querySelector('.terminal-window')
  const guides = document.querySelectorAll('[data-command-guides]')
  const base = scene.getAttribute('data-command-base') || 'pip install packages'
  const finalText = scene.getAttribute('data-command-final') || `s${base}`
  let currentCaretValue = ''
  let resizeFrame = 0

  if (!commandText || !measure || !caret || !copy || !terminalWindow) {
    return
  }

  document.body.classList.add('home-prelude')

  const updateCaretPosition = () => {
    measure.innerHTML = renderCommand(currentCaretValue)
    const width = Math.max(0, measure.getBoundingClientRect().width)
    caret.style.transform = `translateX(${width}px)`
  }

  const setCaret = (value) => {
    currentCaretValue = value
    updateCaretPosition()
  }

  const syncCaret = () => {
    window.cancelAnimationFrame(resizeFrame)
    resizeFrame = window.requestAnimationFrame(updateCaretPosition)
  }

  window.addEventListener('resize', syncCaret)
  if (document.fonts) {
    document.fonts.ready.then(syncCaret)
  }

  const stopBlink = () => {
    caret.classList.remove('is-blinking')
  }

  const startBlink = () => {
    caret.classList.add('is-blinking')
  }

  const setCommand = (value) => {
    commandText.innerHTML = renderCommand(value)
  }

  stopBlink()
  setCommand('')
  setCaret('')
  terminalWindow.classList.remove('is-armed')

  for (let i = 1; i <= base.length; i += 1) {
    const next = base.slice(0, i)
    setCommand(next)
    setCaret(next)
    await sleep(68)
  }

  await sleep(460)

  for (let i = base.length; i >= 0; i -= 1) {
    setCaret(base.slice(0, i))
    await sleep(44)
  }

  await sleep(140)

  setCommand(base)
  setCaret('')

  await sleep(90)

  const prefix = 's'

  for (let i = 1; i <= prefix.length; i += 1) {
    const next = `${prefix.slice(0, i)}${base}`
    setCommand(next)
    setCaret(prefix.slice(0, i))
    await sleep(54)
  }

  terminalWindow.classList.add('is-armed')

  document.body.classList.remove('home-prelude')
  copy.classList.add('is-visible')
  if (message) {
    message.classList.add('is-visible')
  }
  if (scrollCue) {
    scrollCue.classList.add('is-visible')
  }
  for (const guideBlock of guides) {
    guideBlock.classList.add('is-visible')
  }

  await sleep(90)
  const caretText = prefix
  for (let i = caretText.length + 1; i <= finalText.length; i += 1) {
    setCaret(finalText.slice(0, i))
    await sleep(34)
  }
  setCaret(finalText)
  startBlink()
}

for (const scene of scenes) {
  runScene(scene)
}

if (animatedCharts.length > 0) {
  if ('IntersectionObserver' in window) {
    const chartObserver = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) {
            continue
          }
          entry.target.classList.add('is-chart-visible')
          chartObserver.unobserve(entry.target)
        }
      },
      { threshold: 0.35 },
    )

    for (const chart of animatedCharts) {
      chartObserver.observe(chart)
    }
  } else {
    for (const chart of animatedCharts) {
      chart.classList.add('is-chart-visible')
    }
  }
}

for (const button of copyButtons) {
  button.addEventListener('click', async () => {
    const targetId = button.getAttribute('data-copy-target')
    if (!targetId) {
      return
    }

    const source = document.getElementById(targetId)
    if (!(source instanceof HTMLTextAreaElement)) {
      return
    }

    const text = source.value

    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text)
      } else {
        source.focus()
        source.select()
        document.execCommand('copy')
      }
    } catch {
      source.focus()
      source.select()
      document.execCommand('copy')
    }

    const previous = button.textContent
    button.textContent = 'Copied'
    button.classList.add('is-copied')
    window.setTimeout(() => {
      button.textContent = previous
      button.classList.remove('is-copied')
    }, 1200)
  })
}

for (const button of scrollButtons) {
  button.addEventListener('click', () => {
    const section = document.querySelector('[data-why-section]')
    if (section) {
      section.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  })
}

for (const button of installButtons) {
  button.addEventListener('click', () => {
    const section = document.querySelector('[data-download-section]')
    if (section) {
      section.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  })
}

for (const button of nextButtons) {
  button.addEventListener('click', () => {
    const section = document.querySelector('.closing-section')
    if (section) {
      section.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  })
}

for (const button of topButtons) {
  button.addEventListener('click', () => {
    window.scrollTo({ top: 0, behavior: 'smooth' })
  })
}

for (const select of languageSwitches) {
  select.addEventListener('change', () => {
    if (select.value) {
      window.location.href = select.value
    }
  })
}

for (const group of docTabGroups) {
  const tabs = group.querySelectorAll('[data-doc-tab]')
  const panels = group.querySelectorAll('[data-doc-panel]')

  const activate = (key) => {
    for (const tab of tabs) {
      const active = tab.getAttribute('data-doc-tab') === key
      tab.classList.toggle('is-active', active)
      tab.setAttribute('aria-selected', active ? 'true' : 'false')
    }

    for (const panel of panels) {
      const active = panel.getAttribute('data-doc-panel') === key
      panel.classList.toggle('is-active', active)
      panel.hidden = !active
    }
  }

  for (const tab of tabs) {
    tab.addEventListener('click', () => {
      const key = tab.getAttribute('data-doc-tab')
      if (key) {
        activate(key)
      }
    })
  }
}

const docsSearchIndex = {
  en: [
    { title: 'Intro', meta: '/docs/', href: '/docs/' },
    { title: 'Overview', meta: '/docs/#overview', href: '/docs/#overview' },
    { title: 'Install', meta: '/docs/#install', href: '/docs/#install' },
    { title: 'Warning mechanism', meta: '/docs/#warnings', href: '/docs/#warnings' },
    { title: 'Package managers', meta: '/docs/package-managers.html', href: '/docs/package-managers.html' },
    { title: 'Supported managers', meta: '/docs/package-managers.html#support', href: '/docs/package-managers.html#support' },
    { title: 'How to start', meta: '/docs/package-managers.html#start', href: '/docs/package-managers.html#start' },
    { title: 'secpipw options', meta: '/docs/package-managers.html#wrapper-options', href: '/docs/package-managers.html#wrapper-options' },
    { title: 'Refusal behavior', meta: '/docs/package-managers.html#refusals', href: '/docs/package-managers.html#refusals' },
    { title: 'Benchmark', meta: '/docs/benchmark.html', href: '/docs/benchmark.html' },
    { title: 'Checks', meta: '/docs/checks.html', href: '/docs/checks.html' },
    { title: 'typo-suspect check', meta: '/docs/checks.html#check-typo', href: '/docs/checks.html#check-typo' },
    { title: 'direct-url check', meta: '/docs/checks.html#check-direct-url', href: '/docs/checks.html#check-direct-url' },
    { title: 'recent-release check', meta: '/docs/checks.html#check-recent-release', href: '/docs/checks.html#check-recent-release' },
    { title: 'empty-description check', meta: '/docs/checks.html#check-empty-description', href: '/docs/checks.html#check-empty-description' },
    { title: 'yanked-release check', meta: '/docs/checks.html#check-yanked-release', href: '/docs/checks.html#check-yanked-release' },
    { title: 'archive-hash check', meta: '/docs/checks.html#check-archive-hash', href: '/docs/checks.html#check-archive-hash' },
    { title: 'suspicious-url check', meta: '/docs/checks.html#check-suspicious-url', href: '/docs/checks.html#check-suspicious-url' },
    { title: 'repository-mismatch check', meta: '/docs/checks.html#check-repository-mismatch', href: '/docs/checks.html#check-repository-mismatch' },
    { title: 'email-domain-drift check', meta: '/docs/checks.html#check-email-domain-drift', href: '/docs/checks.html#check-email-domain-drift' },
    { title: 'zero-version check', meta: '/docs/checks.html#check-zero-version', href: '/docs/checks.html#check-zero-version' },
    { title: 'suspicious-pth check', meta: '/docs/checks.html#check-suspicious-pth', href: '/docs/checks.html#check-suspicious-pth' },
    { title: 'artifact-history check', meta: '/docs/checks.html#check-artifact-history', href: '/docs/checks.html#check-artifact-history' },
    { title: 'Workflow', meta: '/docs/#workflow', href: '/docs/#workflow' },
    { title: 'Next', meta: '/docs/#next', href: '/docs/#next' },
    { title: 'Parameters', meta: '/docs/parameters.html', href: '/docs/parameters.html' },
    { title: 'Command shape', meta: '/docs/parameters.html#command-shape', href: '/docs/parameters.html#command-shape' },
    { title: 'secpipw install options', meta: '/docs/parameters.html#install-options', href: '/docs/parameters.html#install-options' },
    { title: '--spip-ignore-warning', meta: '/docs/parameters.html#ignore-warning', href: '/docs/parameters.html#ignore-warning' },
    { title: '--spip-ignore', meta: '/docs/parameters.html#ignore', href: '/docs/parameters.html#ignore' },
    { title: '--spip-debug', meta: '/docs/parameters.html#debug', href: '/docs/parameters.html#debug' },
    { title: '--spip-status', meta: '/docs/parameters.html#spip-status', href: '/docs/parameters.html#spip-status' },
    { title: '--sensitivity', meta: '/docs/parameters.html#sensitivity', href: '/docs/parameters.html#sensitivity' },
    { title: 'Pip passthrough', meta: '/docs/parameters.html#passthrough', href: '/docs/parameters.html#passthrough' },
  ],
  zh: [
    { title: '介绍', meta: '/zh-cn/docs/', href: '/zh-cn/docs/' },
    { title: '概览', meta: '/zh-cn/docs/#overview', href: '/zh-cn/docs/#overview' },
    { title: '安装', meta: '/zh-cn/docs/#install', href: '/zh-cn/docs/#install' },
    { title: '报警机制', meta: '/zh-cn/docs/#warnings', href: '/zh-cn/docs/#warnings' },
    { title: '包管理器', meta: '/zh-cn/docs/package-managers.html', href: '/zh-cn/docs/package-managers.html' },
    { title: '已支持的管理器', meta: '/zh-cn/docs/package-managers.html#support', href: '/zh-cn/docs/package-managers.html#support' },
    { title: '如何启动', meta: '/zh-cn/docs/package-managers.html#start', href: '/zh-cn/docs/package-managers.html#start' },
    { title: 'secpipw 参数位置', meta: '/zh-cn/docs/package-managers.html#wrapper-options', href: '/zh-cn/docs/package-managers.html#wrapper-options' },
    { title: '拒绝执行的情况', meta: '/zh-cn/docs/package-managers.html#refusals', href: '/zh-cn/docs/package-managers.html#refusals' },
    { title: 'Benchmark 基准测试', meta: '/zh-cn/docs/benchmark.html', href: '/zh-cn/docs/benchmark.html' },
    { title: '检查项', meta: '/zh-cn/docs/checks.html', href: '/zh-cn/docs/checks.html' },
    { title: 'typo-suspect 检查', meta: '/zh-cn/docs/checks.html#check-typo', href: '/zh-cn/docs/checks.html#check-typo' },
    { title: 'direct-url 检查', meta: '/zh-cn/docs/checks.html#check-direct-url', href: '/zh-cn/docs/checks.html#check-direct-url' },
    { title: 'recent-release 检查', meta: '/zh-cn/docs/checks.html#check-recent-release', href: '/zh-cn/docs/checks.html#check-recent-release' },
    { title: 'empty-description 检查', meta: '/zh-cn/docs/checks.html#check-empty-description', href: '/zh-cn/docs/checks.html#check-empty-description' },
    { title: 'yanked-release 检查', meta: '/zh-cn/docs/checks.html#check-yanked-release', href: '/zh-cn/docs/checks.html#check-yanked-release' },
    { title: 'archive-hash 检查', meta: '/zh-cn/docs/checks.html#check-archive-hash', href: '/zh-cn/docs/checks.html#check-archive-hash' },
    { title: 'suspicious-url 检查', meta: '/zh-cn/docs/checks.html#check-suspicious-url', href: '/zh-cn/docs/checks.html#check-suspicious-url' },
    { title: 'repository-mismatch 检查', meta: '/zh-cn/docs/checks.html#check-repository-mismatch', href: '/zh-cn/docs/checks.html#check-repository-mismatch' },
    { title: 'email-domain-drift 检查', meta: '/zh-cn/docs/checks.html#check-email-domain-drift', href: '/zh-cn/docs/checks.html#check-email-domain-drift' },
    { title: 'zero-version 检查', meta: '/zh-cn/docs/checks.html#check-zero-version', href: '/zh-cn/docs/checks.html#check-zero-version' },
    { title: 'suspicious-pth 检查', meta: '/zh-cn/docs/checks.html#check-suspicious-pth', href: '/zh-cn/docs/checks.html#check-suspicious-pth' },
    { title: 'artifact-history 检查', meta: '/zh-cn/docs/checks.html#check-artifact-history', href: '/zh-cn/docs/checks.html#check-artifact-history' },
    { title: '工作流', meta: '/zh-cn/docs/#workflow', href: '/zh-cn/docs/#workflow' },
    { title: '下一步', meta: '/zh-cn/docs/#next', href: '/zh-cn/docs/#next' },
    { title: '参数说明', meta: '/zh-cn/docs/parameters.html', href: '/zh-cn/docs/parameters.html' },
    { title: '命令结构', meta: '/zh-cn/docs/parameters.html#command-shape', href: '/zh-cn/docs/parameters.html#command-shape' },
    { title: 'secpipw install 参数', meta: '/zh-cn/docs/parameters.html#install-options', href: '/zh-cn/docs/parameters.html#install-options' },
    { title: '--spip-ignore-warning', meta: '/zh-cn/docs/parameters.html#ignore-warning', href: '/zh-cn/docs/parameters.html#ignore-warning' },
    { title: '--spip-ignore', meta: '/zh-cn/docs/parameters.html#ignore', href: '/zh-cn/docs/parameters.html#ignore' },
    { title: '--spip-debug', meta: '/zh-cn/docs/parameters.html#debug', href: '/zh-cn/docs/parameters.html#debug' },
    { title: '--spip-status', meta: '/zh-cn/docs/parameters.html#spip-status', href: '/zh-cn/docs/parameters.html#spip-status' },
    { title: '--sensitivity', meta: '/zh-cn/docs/parameters.html#sensitivity', href: '/zh-cn/docs/parameters.html#sensitivity' },
    { title: 'pip 参数透传', meta: '/zh-cn/docs/parameters.html#passthrough', href: '/zh-cn/docs/parameters.html#passthrough' },
  ],
}

const currentDocsSearchLang = window.location.pathname.startsWith('/zh-cn/')
  ? 'zh'
  : 'en'

const renderDocsSearchResults = (query) => {
  if (!docsSearchResults) {
    return
  }

  const normalized = query.trim().toLowerCase()
  const items = docsSearchIndex[currentDocsSearchLang]
  const matches = normalized
    ? items.filter((item) =>
        `${item.title} ${item.meta}`.toLowerCase().includes(normalized),
      )
    : items

  if (matches.length === 0) {
    docsSearchResults.innerHTML = `<div class="docs-search-empty">${
      currentDocsSearchLang === 'zh' ? '没有匹配结果。' : 'No matches found.'
    }</div>`
    return
  }

  docsSearchResults.innerHTML = matches
    .map(
      (item) => `
        <a class="docs-search-result" href="${item.href}">
          <span class="docs-search-result-title">${escapeHtml(item.title)}</span>
          <span class="docs-search-result-meta">${escapeHtml(item.meta)}</span>
        </a>
      `,
    )
    .join('')
}

const openDocsSearch = () => {
  if (!docsSearchModal || !docsSearchInput) {
    return
  }
  docsSearchModal.hidden = false
  renderDocsSearchResults('')
  window.setTimeout(() => docsSearchInput.focus(), 0)
}

const closeDocsSearch = () => {
  if (!docsSearchModal || !docsSearchInput) {
    return
  }
  docsSearchModal.hidden = true
  docsSearchInput.value = ''
}

for (const trigger of docsSearchTriggers) {
  trigger.addEventListener('click', openDocsSearch)
}

if (docsSearchModal && docsSearchInput && docsSearchResults) {
  docsSearchInput.addEventListener('input', () => {
    renderDocsSearchResults(docsSearchInput.value)
  })

  docsSearchModal.addEventListener('click', (event) => {
    if (event.target === docsSearchModal) {
      closeDocsSearch()
    }
  })

  document.addEventListener('keydown', (event) => {
    const isOpen = !docsSearchModal.hidden
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault()
      if (isOpen) {
        closeDocsSearch()
      } else {
        openDocsSearch()
      }
      return
    }

    if (event.key === 'Escape' && isOpen) {
      event.preventDefault()
      closeDocsSearch()
    }
  })
}
