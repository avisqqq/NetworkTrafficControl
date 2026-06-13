export function fitPopover(node) {
  function fit() {
    const popover = node.querySelector('.device-popover')
    if (!popover) return

    const margin = 12
    popover.style.setProperty('--popover-shift', '0px')
    popover.style.setProperty('--popover-shift-y', '0px')

    const rect = popover.getBoundingClientRect()
    let shift = 0
    let shiftY = 0

    if (rect.right > window.innerWidth - margin) {
      shift -= rect.right - (window.innerWidth - margin)
    }

    if (rect.left + shift < margin) {
      shift += margin - (rect.left + shift)
    }

    if (rect.bottom > window.innerHeight - margin) {
      shiftY -= rect.bottom - (window.innerHeight - margin)
    }

    if (rect.top + shiftY < margin) {
      shiftY += margin - (rect.top + shiftY)
    }

    popover.style.setProperty('--popover-shift', `${shift}px`)
    popover.style.setProperty('--popover-shift-y', `${shiftY}px`)
  }

  node.addEventListener('pointerenter', fit)
  node.addEventListener('focusin', fit)
  window.addEventListener('resize', fit)

  return {
    destroy() {
      node.removeEventListener('pointerenter', fit)
      node.removeEventListener('focusin', fit)
      window.removeEventListener('resize', fit)
    },
  }
}
