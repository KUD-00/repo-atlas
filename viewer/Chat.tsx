import { useEffect, useRef, useState } from 'react'
import type { ChatMessage } from '../src/types'
import { useLive } from './live'

/** Floating "attach to chat" pill that appears when a text selection is
 * released anywhere outside the chat dock. */
function SelectionAttach({ onAttach }: { onAttach: (text: string) => void }) {
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null)
  const textRef = useRef('')
  useEffect(() => {
    const onUp = (e: globalThis.MouseEvent) => {
      if ((e.target as HTMLElement).closest?.('.chat-dock, .sel-attach')) return
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
        setPos({
          x: Math.max(8, Math.min(x + 6, window.innerWidth - 150)),
          y: Math.max(8, Math.min(y + 14, window.innerHeight - 40)),
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
      className="sel-attach"
      style={{ left: pos.x, top: pos.y }}
      onMouseDown={(e) => e.preventDefault()} // keep the selection alive through the click
      onClick={() => {
        onAttach(textRef.current)
        setPos(null)
        window.getSelection()?.removeAllRanges()
      }}
    >
      ⤷ attach to chat
    </button>
  )
}

interface Attachment {
  id: number
  from: string
  text: string
}

export function ChatDock({ currentPath }: { currentPath: string }) {
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

  if (!live) return null
  if (!open) {
    return (
      <>
        <SelectionAttach onAttach={addAttachment} />
        <button className="chat-fab" onClick={() => setOpen(true)} title="chat with the attached agent session">
          chat{connected && <span className="chat-dot on" />}
        </button>
      </>
    )
  }
  return (
    <>
    <SelectionAttach onAttach={addAttachment} />
    <div
      className={'chat-dock' + (closing ? ' closing' : '')}
      onAnimationEnd={(e) => {
        if (closing && e.target === e.currentTarget) {
          setClosing(false)
          setOpen(false)
        }
      }}
    >
      <div className="chat-head">
        <span className={'chat-dot' + (connected ? ' on' : '')} />
        <span className="chat-title">{connected ? 'agent connected' : 'no agent polling'}</span>
        <button className="chat-x" onClick={() => setClosing(true)}>×</button>
      </div>
      <div className="chat-list" ref={listRef}>
        {messages.length === 0 && (
          <div className="chat-hint">
            Messages go to whichever agent session is polling <code>/chat/poll</code>.
            {!connected && ' None is right now — attach one first.'}
          </div>
        )}
        {messages.map((m) => (
          <div key={m.id} className={'chat-msg ' + m.role + (m.cancelled ? ' cancelled' : '')}>
            {m.role === 'user' && m.context && <div className="chat-ctx">@ {m.context}</div>}
            <div className="chat-text">{m.text}</div>
            {m.cancelled && <div className="chat-ctx">已撤回</div>}
          </div>
        ))}
        {working && (
          <div className="chat-msg agent">
            {progress && <div className="chat-progress">{progress}</div>}
            <div className="chat-text chat-typing"><span /><span /><span /></div>
          </div>
        )}
      </div>
      {retractable && (
        <div className="chat-retract">
          <button className="btn" onClick={cancel}>撤回上一条{working ? '（agent 已在处理，将尽快停止）' : ''}</button>
        </div>
      )}
      {attachments.length > 0 && (
        <div className="chat-attachments">
          {attachments.map((a) => (
            <div key={a.id} className="chat-att">
              <div className="chat-att-body">
                <div className="chat-att-from">@ {a.from}</div>
                <div className="chat-att-text">{a.text}</div>
              </div>
              <button
                className="chat-x"
                onClick={() => setAttachments((x) => x.filter((y) => y.id !== a.id))}
              >
                ×
              </button>
            </div>
          ))}
        </div>
      )}
      <div className="chat-input">
        <textarea
          rows={2}
          placeholder="message the agent… (⏎ send, ⇧⏎ newline)"
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
        <button className="btn primary" onClick={send} disabled={!text.trim() && !attachments.length}>send</button>
      </div>
    </div>
    </>
  )
}