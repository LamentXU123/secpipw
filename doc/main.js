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

  if (!commandText || !measure || !caret || !copy || !terminalWindow) {
    return
  }

  document.body.classList.add('home-prelude')

  const setCaret = (value) => {
    measure.innerHTML = renderCommand(value)
    const width = Math.max(0, measure.getBoundingClientRect().width + 3)
    caret.style.transform = `translateX(${width}px)`
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
  for (let i = 2; i <= finalText.length; i += 1) {
    setCaret(finalText.slice(0, i))
    await sleep(34)
  }
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
    { title: 'Workflow', meta: '/docs/#workflow', href: '/docs/#workflow' },
    { title: 'Next', meta: '/docs/#next', href: '/docs/#next' },
    { title: 'Parameters', meta: '/docs/parameters.html', href: '/docs/parameters.html' },
    { title: 'Command shape', meta: '/docs/parameters.html#command-shape', href: '/docs/parameters.html#command-shape' },
    { title: 'secured_pip install options', meta: '/docs/parameters.html#install-options', href: '/docs/parameters.html#install-options' },
    { title: '--ignore-warning', meta: '/docs/parameters.html#ignore-warning', href: '/docs/parameters.html#ignore-warning' },
    { title: '--debug', meta: '/docs/parameters.html#debug', href: '/docs/parameters.html#debug' },
    { title: '--spip-status', meta: '/docs/parameters.html#spip-status', href: '/docs/parameters.html#spip-status' },
    { title: '--sensitivity', meta: '/docs/parameters.html#sensitivity', href: '/docs/parameters.html#sensitivity' },
    { title: 'Top-level secured_pip commands', meta: '/docs/parameters.html#top-level', href: '/docs/parameters.html#top-level' },
    { title: 'Pip passthrough', meta: '/docs/parameters.html#passthrough', href: '/docs/parameters.html#passthrough' },
  ],
  zh: [
    { title: '介绍', meta: '/zh-cn/docs/', href: '/zh-cn/docs/' },
    { title: '概览', meta: '/zh-cn/docs/#overview', href: '/zh-cn/docs/#overview' },
    { title: '安装', meta: '/zh-cn/docs/#install', href: '/zh-cn/docs/#install' },
    { title: '报警机制', meta: '/zh-cn/docs/#warnings', href: '/zh-cn/docs/#warnings' },
    { title: '工作流', meta: '/zh-cn/docs/#workflow', href: '/zh-cn/docs/#workflow' },
    { title: '下一步', meta: '/zh-cn/docs/#next', href: '/zh-cn/docs/#next' },
    { title: '参数说明', meta: '/zh-cn/docs/parameters.html', href: '/zh-cn/docs/parameters.html' },
    { title: '命令结构', meta: '/zh-cn/docs/parameters.html#command-shape', href: '/zh-cn/docs/parameters.html#command-shape' },
    { title: 'secured_pip install 参数', meta: '/zh-cn/docs/parameters.html#install-options', href: '/zh-cn/docs/parameters.html#install-options' },
    { title: '--ignore-warning', meta: '/zh-cn/docs/parameters.html#ignore-warning', href: '/zh-cn/docs/parameters.html#ignore-warning' },
    { title: '--debug', meta: '/zh-cn/docs/parameters.html#debug', href: '/zh-cn/docs/parameters.html#debug' },
    { title: '--spip-status', meta: '/zh-cn/docs/parameters.html#spip-status', href: '/zh-cn/docs/parameters.html#spip-status' },
    { title: '--sensitivity', meta: '/zh-cn/docs/parameters.html#sensitivity', href: '/zh-cn/docs/parameters.html#sensitivity' },
    { title: '顶层 secured_pip 命令', meta: '/zh-cn/docs/parameters.html#top-level', href: '/zh-cn/docs/parameters.html#top-level' },
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
