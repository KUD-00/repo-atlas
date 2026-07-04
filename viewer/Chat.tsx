import { useEffect, useRef, useState } from 'react'
import { t } from '@lingui/core/macro'
import { Trans, useLingui } from '@lingui/react/macro'
import type { ChatMessage } from '../src/types'
import { useLive } from './live'

const BTN =
  'btn font-inherit text-[0.75rem] py-[5px] px-3 rounded-lg border border-border bg-panel text-text cursor-pointer whitespace-nowrap hover:border-accent hover:text-accent disabled:opacity-50 disabled:cursor-default'

/** Floating "attach to chat" pill that appears when a text selection is
 * released anywhere outside the chat dock. */
function SelectionAttach({ onAttach }: { onAttach: (text: string) => void }) {
  const { i18n } = useLingui()
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null)
  const textRef = useRef('')
  useEffect(() => {
    const onUp = (e: globalThis.MouseEvent) => {
      if ((e.target as HTMLElement).closest?.('.chat-dock, .chat-sheet, .sel-attach')) return
      // anchor the button to the RELEASE POINT — a selection's bounding rect
      // can be far away (upward drags, multi-line, h-scrolled code)
      const x = e.clientX
      const y = e.clientY
      // selection is finalized a tick after mouseup
      setTimeout(() => {
        const sel = window.getSelection()
        const text = sel?.toString().trim() ?? ''
        if (!sel || sel.isCollapsed || !text) {
          setPos(null)
          return
        }
        textRef.current = text
        const margin = 12
        const btnW = 150
        const btnH = 40
        setPos({
          x: Math.max(margin, Math.min(x + 6, window.innerWidth - btnW - margin)),
          y: Math.max(margin, Math.min(y + 14, window.innerHeight - btnH - margin)),
        })
      }, 0)
    }
    const onDown = (e: globalThis.MouseEvent) => {
      if (!(e.target as HTMLElement).closest?.('.sel-attach')) setPos(null)
    }
    document.addEventListener('mouseup', onUp)
    document.addEventListener('mousedown', onDown)
    return () => {
      document.removeEventListener('mouseup', onUp)
      document.removeEventListener('mousedown', onDown)
    }
  }, [])
  if (!pos) return null
  return (
    <button
      className="sel-attach fixed z-40 font-inherit text-[0.72rem] py-1 px-2.5 rounded-full border border-accent bg-panel text-accent cursor-pointer shadow-[0_3px_12px_#00000022] whitespace-nowrap animate-[chat-in_0.12s_ease] hover:bg-[linear-gradient(#3d6b5412,#3d6b5412),var(--color-panel)]"
      style={{ left: pos.x, top: pos.y }}
      onMouseDown={(e) => e.preventDefault()} // keep the selection alive through the click
      onClick={() => {
        onAttach(textRef.current)
        setPos(null)
        window.getSelection()?.removeAllRanges()
      }}
    >
      {t(i18n)`⤷ attach to chat`}
    </button>
  )
}

interface Attachment {
  id: number
  from: string
  text: string
}

export function ChatDock({ currentPath, compact }: { currentPath: string; compact?: boolean }) {
  const { i18n } = useLingui()
  const live = useLive()
  const [open, setOpen] = useState(() => sessionStorage.getItem('atlas-chat-open') === '1')
  const [closing, setClosing] = useState(false)
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [connected, setConnected] = useState(false)
  const [working, setWorking] = useState(false)
  const [progress, setProgress] = useState<string | null>(null)
  const [text, setText] = useState('')
  const [attachments, setAttachments] = useState<Attachment[]>([])
  const attachSeq = useRef(0)
  const listRef = useRef<HTMLDivElement>(null)
  const pathRef = useRef(currentPath)
  pathRef.current = currentPath

  const addAttachment = (t: string) => {
    setAttachments((a) => [...a, { id: ++attachSeq.current, from: pathRef.current || '(root)', text: t }])
    setOpen(true)
    setClosing(false)
  }

  useEffect(() => {
    if (!live) return
    fetch('chat/history')
      .then((r) => r.json())
      .then((d: {
        messages: ChatMessage[]
        connected: boolean
        working: boolean
        progress?: string | null
      }) => {
        setMessages(d.messages)
        setConnected(d.connected)
        setWorking(d.working)
        setProgress(d.progress ?? null)
      })
      .catch(() => {})
    const es = new EventSource('events')
    es.addEventListener('chat', (e) => {
      const msg = JSON.parse(e.data) as ChatMessage & {
        type?: string
        connected?: boolean
        working?: boolean
        text?: string | null
        id?: string
      }
      if (msg.type === 'status') {
        setConnected(Boolean(msg.connected))
        setWorking(Boolean(msg.working))
        if (!msg.working) setProgress(null)
      } else if (msg.type === 'progress') {
        setProgress(msg.text ?? null)
      } else if (msg.type === 'cancelled') {
        setMessages((m) => m.map((x) => (x.id === msg.id ? { ...x, cancelled: true } : x)))
      } else {
        setMessages((m) => (m.some((x) => x.id === msg.id) ? m : [...m, msg as ChatMessage]))
      }
    })
    return () => es.close()
  }, [live])

  // compact top bar owns the launcher; it toggles the dock through this event
  useEffect(() => {
    const onToggle = () => {
      setClosing(false)
      setOpen((o) => !o)
    }
    window.addEventListener('atlas-chat-toggle', onToggle)
    return () => window.removeEventListener('atlas-chat-toggle', onToggle)
  }, [])

  useEffect(() => sessionStorage.setItem('atlas-chat-open', open ? '1' : '0'), [open])
  useEffect(() => {
    listRef.current?.scrollTo(0, 1e9)
  }, [messages, open])

  const send = () => {
    const t = text.trim()
    if (!t && !attachments.length) return
    // attached selections travel inside the message as quoted blocks
    const quoted = attachments
      .map((a) => `【选中 @ ${a.from}】\n${a.text}`)
      .join('\n\n')
    const full = quoted ? (t ? `${quoted}\n\n${t}` : quoted) : t
    setText('')
    setAttachments([])
    fetch('chat/send', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text: full, context: pathRef.current || '(root)' }),
    }).catch(() => {})
  }

  const last = messages[messages.length - 1]
  const retractable = last?.role === 'user' && !last.cancelled ? last : null
  const cancel = () =>
    retractable &&
    fetch('chat/cancel', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: retractable.id }),
    }).catch(() => {})

  // selections are only worth attaching when an agent is actually listening
  const attachPill = connected ? <SelectionAttach onAttach={addAttachment} /> : null

  if (!live) return null
  if (!open) {
    // on compact the top bar is the launcher — only the selection pill floats
    if (compact) return attachPill
    return (
      <>
        {attachPill}
        <button
          className="fixed right-3 bottom-3 md:right-5 md:bottom-5 z-20 font-inherit text-[0.8rem] py-2 px-4 rounded-full border border-border bg-panel text-text cursor-pointer shadow-[0_2px_10px_#00000018] inline-flex items-center gap-[7px] origin-bottom-right animate-[chat-in_0.16s_ease] hover:border-accent hover:text-accent"
          onClick={() => setOpen(true)}
          title={t(i18n)`chat with the attached agent session`}
        >
          {t(i18n)`chat`}
          {connected && <span className="w-2 h-2 rounded-full shrink-0 bg-fresh" />}
        </button>
      </>
    )
  }
  return (
    <>
    {attachPill}
    {compact && (
      <div
        className={
          'fixed inset-0 z-20 bg-[#00000033] ' +
          (closing ? 'animate-[fade-out_0.16s_ease_forwards]' : 'animate-[fade-in_0.2s_ease]')
        }
        onClick={() => setClosing(true)}
        aria-hidden
      />
    )}
    <div
      className={
        'fixed z-20 flex flex-col bg-panel overflow-hidden ' +
        (compact
          ? 'chat-sheet inset-x-0 bottom-0 w-full h-[min(560px,80dvh)] border-t border-border rounded-t-xl shadow-[0_-6px_28px_#00000026] ' +
            (closing ? 'animate-[sheet-out_0.18s_ease_forwards]' : 'animate-[sheet-in_0.22s_ease]')
          : 'chat-dock right-5 bottom-5 w-[380px] h-[480px] max-h-[calc(100dvh-40px)] border border-border rounded-xl shadow-[0_6px_28px_#00000026] origin-bottom-right ' +
            (closing ? 'animate-[chat-out_0.16s_ease_forwards]' : 'animate-[chat-in_0.2s_ease]'))
      }
      onAnimationEnd={(e) => {
        if (closing && e.target === e.currentTarget) {
          setClosing(false)
          setOpen(false)
        }
      }}
    >
      <div className="flex items-center gap-2 py-2.5 px-3 border-b border-border text-[0.78rem] shrink-0">
        <span
          className={
            'w-2 h-2 rounded-full shrink-0 ' +
            (connected ? 'bg-fresh' : 'bg-none border-[1.5px] border-missing')
          }
        />
        <span className="text-muted">{connected ? t(i18n)`agent connected` : t(i18n)`no agent polling`}</span>
        <button
          className="ml-auto font-inherit text-base leading-none border-none bg-transparent text-muted cursor-pointer py-0.5 px-1.5 hover:text-text"
          onClick={() => setClosing(true)}
        >
          ×
        </button>
      </div>
      <div className="flex-1 min-h-0 overflow-y-auto p-3 flex flex-col gap-2" ref={listRef}>
        {messages.length === 0 && (
          <div className="text-muted text-[0.78rem] leading-normal [&_code]:bg-[#00000009] [&_code]:py-[0.1em] [&_code]:px-[0.4em] [&_code]:rounded">
            <Trans>
              Messages go to whichever agent session is polling <code>/chat/poll</code>.
            </Trans>
            {!connected && ` ${t(i18n)`None is right now — attach one first.`}`}
          </div>
        )}
        {messages.map((m) => (
          <div
            key={m.id}
            className={
              'max-w-[88%] text-[0.82rem] leading-normal ' +
              (m.role === 'user' ? 'self-end ' : 'self-start ') +
              (m.cancelled ? 'opacity-[0.45] [&_.chat-text]:line-through' : '')
            }
          >
            {m.role === 'user' && m.context && (
              <div className="text-[0.68rem] text-muted mx-1 mb-0.5 text-right font-mono">@ {m.context}</div>
            )}
            <div
              className={
                'chat-text py-[7px] px-[11px] rounded-[10px] whitespace-pre-wrap break-words ' +
                (m.role === 'user'
                  ? 'bg-accent text-white rounded-br-[3px]'
                  : 'bg-[#00000008] border border-border rounded-bl-[3px]')
              }
            >
              {m.text}
            </div>
            {m.cancelled && (
              <div className="text-[0.68rem] text-muted mx-1 mb-0.5 text-right font-mono">{t(i18n)`retracted`}</div>
            )}
          </div>
        ))}
        {working && (
          <div className="max-w-[88%] text-[0.82rem] leading-normal self-start">
            {progress && <div className="text-[0.72rem] text-muted italic mx-1 mb-[3px]">{progress}</div>}
            <div className="chat-text chat-typing inline-flex gap-1 items-center min-h-[1.2em] py-[7px] px-[11px] rounded-[10px] bg-[#00000008] border border-border rounded-bl-[3px]">
              <span className="w-1.5 h-1.5 rounded-full bg-muted" />
              <span className="w-1.5 h-1.5 rounded-full bg-muted" />
              <span className="w-1.5 h-1.5 rounded-full bg-muted" />
            </div>
          </div>
        )}
      </div>
      {retractable && (
        <div className="py-1.5 px-3 pt-0 shrink-0 flex justify-end">
          <button className={BTN + ' text-[0.7rem] py-0.5 px-2.5'} onClick={cancel}>
            {working ? t(i18n)`retract last message (agent is already on it)` : t(i18n)`retract last message`}
          </button>
        </div>
      )}
      {attachments.length > 0 && (
        <div className="shrink-0 max-h-[130px] overflow-y-auto pt-2 px-3 flex flex-col gap-1.5 border-t border-border">
          {attachments.map((a) => (
            <div
              key={a.id}
              className="flex items-start gap-1 border border-border border-l-[3px] border-l-accent rounded-md py-[5px] px-2 bg-bg"
            >
              <div className="min-w-0 flex-1">
                <div className="text-[0.65rem] text-muted font-mono">@ {a.from}</div>
                <div className="text-[0.72rem] leading-[1.45] text-text line-clamp-3 whitespace-pre-wrap break-words">
                  {a.text}
                </div>
              </div>
              <button
                className="font-inherit text-base leading-none border-none bg-transparent text-muted cursor-pointer py-0.5 px-1.5 hover:text-text"
                onClick={() => setAttachments((x) => x.filter((y) => y.id !== a.id))}
              >
                ×
              </button>
            </div>
          ))}
        </div>
      )}
      <div className="flex gap-2 py-2.5 px-3 border-t border-border shrink-0">
        <textarea
          rows={2}
          className="flex-1 min-w-0 resize-none font-inherit text-[0.82rem] leading-normal py-[7px] px-2.5 border border-border rounded-lg bg-bg text-text focus:outline-none focus:border-accent"
          placeholder={t(i18n)`message the agent… (⏎ send, ⇧⏎ newline)`}
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            // an Enter that confirms an IME candidate must not send the message
            if (e.nativeEvent.isComposing || e.keyCode === 229) return
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault()
              send()
            }
          }}
        />
        <button
          className={BTN + ' bg-accent border-accent text-white hover:opacity-90'}
          onClick={send}
          disabled={!text.trim() && !attachments.length}
        >
          {t(i18n)`send`}
        </button>
      </div>
    </div>
    </>
  )
}