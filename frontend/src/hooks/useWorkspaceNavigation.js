import { useCallback, useEffect, useRef, useState } from 'react'
import { helpTopicFromHash, moduleFromHash, workspaceHash } from '../services/workspaceNavigation.js'

export default function useWorkspaceNavigation() {
  const [activeModule, setActiveModule] = useState(() => moduleFromHash(window.location.hash))
  const [helpTopic, setHelpTopic] = useState(() => helpTopicFromHash(window.location.hash))
  const initialModulePosition = useRef(true)

  useEffect(() => {
    if (!('scrollRestoration' in window.history)) return undefined
    const previousScrollRestoration = window.history.scrollRestoration
    window.history.scrollRestoration = 'manual'
    return () => {
      window.history.scrollRestoration = previousScrollRestoration
    }
  }, [])

  useEffect(() => {
    const syncFromLocation = () => {
      setActiveModule(moduleFromHash(window.location.hash))
      setHelpTopic(helpTopicFromHash(window.location.hash))
    }
    window.addEventListener('hashchange', syncFromLocation)
    return () => window.removeEventListener('hashchange', syncFromLocation)
  }, [])

  useEffect(() => {
    // Keep initial focus neutral so keyboard users can reach the skip link first.
    const keepInitialTabOrder = initialModulePosition.current
    const frame = window.requestAnimationFrame(() => {
      const heading = document.getElementById(`workspace-heading-${activeModule}`)
      if (!heading) return
      scrollToVisibleTarget(heading, { focus: !keepInitialTabOrder })
      if (keepInitialTabOrder) initialModulePosition.current = false
    })
    return () => window.cancelAnimationFrame(frame)
  }, [activeModule])

  useEffect(() => {
    const updateScrollInset = () => {
      const heading = document.getElementById(`workspace-heading-${activeModule}`)
      if (heading) updateWorkspaceScrollPadding(heading)
    }
    const observer = window.ResizeObserver ? new window.ResizeObserver(updateScrollInset) : null
    for (const selector of ['.dashboard-header', '.app-sidebar']) {
      const element = document.querySelector(selector)
      if (element) observer?.observe(element)
    }
    window.addEventListener('resize', updateScrollInset)
    updateScrollInset()
    return () => {
      observer?.disconnect()
      window.removeEventListener('resize', updateScrollInset)
    }
  }, [activeModule])

  const navigateToModule = useCallback((moduleId, topicId = '') => {
    const nextHash = workspaceHash(moduleId, topicId)
    setActiveModule(moduleId)
    if (moduleId === 'help' && topicId) setHelpTopic(topicId)
    if (window.location.hash !== nextHash) window.location.hash = nextHash
  }, [])

  const selectHelpTopic = useCallback((topicId) => {
    const nextHash = workspaceHash('help', topicId)
    setHelpTopic(topicId)
    if (window.location.hash !== nextHash) {
      window.history.replaceState(window.history.state, '', nextHash)
    }
  }, [])

  return { activeModule, helpTopic, navigateToModule, selectHelpTopic }
}

export function scrollToVisibleTarget(target, { focus = false, preserveVisible = false } = {}) {
  if (!target?.isConnected) return false
  if (focus) target.focus({ preventScroll: true })

  const targetRect = target.getBoundingClientRect()
  const desiredTop = updateWorkspaceScrollPadding(target)
  if (preserveVisible
      && targetRect.top >= desiredTop
      && targetRect.bottom <= window.innerHeight) return true

  const delta = targetRect.top - desiredTop
  if (Math.abs(delta) < 1) return true

  const reducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
  const top = Math.max(0, window.scrollY + delta)
  if (reducedMotion) window.scrollTo(0, top)
  else window.scrollTo({ top, behavior: 'smooth' })
  return true
}

export function updateWorkspaceScrollPadding(target) {
  if (!target?.isConnected) return 0
  const targetRect = target.getBoundingClientRect()
  const clearance = Number.parseFloat(
    window.getComputedStyle(document.documentElement).getPropertyValue('--workspace-clearance'),
  ) || 28
  const overlappingStickyBottoms = ['.dashboard-header', '.app-sidebar']
    .map((selector) => document.querySelector(selector))
    .filter((element) => {
      if (!element) return false
      const style = window.getComputedStyle(element)
      if (!['sticky', 'fixed'].includes(style.position)) return false
      const rect = element.getBoundingClientRect()
      const overlapsHorizontally = rect.left < targetRect.right && rect.right > targetRect.left
      return overlapsHorizontally && rect.top <= 1 && rect.bottom > 0
    })
    .reduce((bottom, element) => Math.max(bottom, element.getBoundingClientRect().bottom), 0)

  const desiredTop = overlappingStickyBottoms + clearance
  document.documentElement.style.setProperty(
    '--workspace-scroll-inset',
    `${Math.ceil(desiredTop)}px`,
  )
  return desiredTop
}

export function skipToWorkspaceMain(event, activeModule) {
  event.preventDefault()
  const target = document.getElementById(`workspace-heading-${activeModule}`)
    ?? document.getElementById('main-content')
  if (!target || target.closest?.('[hidden], [inert]')) return false
  return scrollToVisibleTarget(target, { focus: true, preserveVisible: true })
}
