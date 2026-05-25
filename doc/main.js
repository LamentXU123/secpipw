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
