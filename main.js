// ===== 設定 =====
const SUPABASE_URL = "https://vshprfqrpicimjboiwjt.supabase.co";
const SUPABASE_ANON_KEY = "sb_publishable_X8UkIz_-yKic4cxHC0_QQw_5EojlmIa";

if (!window.supabase) {
  throw new Error('ライブラリの読み込みに失敗しました（バージョン固定またはSRIの不一致の可能性）。index.html の script タグを確認してください');
}
const sb = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// 暗号文の形式：v2 = AAD（id / 送信者 / 受信者）付き。接頭辞なし = 旧形式
const FORMAT_PREFIX = 'v2:';
// 旧形式を受け付ける期限。この日時より前に作成された行のみ旧形式を復号する（24時間自動削除のため自然に不要になる）
const LEGACY_CUTOFF_MS = Date.parse('2026-11-08T00:00:00Z');
const DECRYPT_ERROR = '[復号エラー：合言葉不一致または未暗号化データ]';

let myUserId = null;
let partnerUserId = localStorage.getItem('partnerUserId');
if (partnerUserId === 'null' || partnerUserId === '') partnerUserId = null;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
if (partnerUserId && !UUID_RE.test(partnerUserId)) partnerUserId = null;

let allMessages = [];
let searchTerm = '';
let replyTarget = null;
let editingId = null;
let typingChannel = null;
let typingTimeout = null;
let presenceChannel = null;
let partnerOnline = false;
let partnerLastSeen = null;
let cryptoKey = null;
let vaultKey = null;
let logVisible = false;
let roomPollTimer = null;
let markReadWarned = false;
let renderSeq = 0;
const plainCache = new Map(); // id -> { content, reply, plain, replyPlain }

const te = new TextEncoder();
const td = new TextDecoder();

function formatTime(ts) {
  const d = new Date(ts);
  return d.getHours().toString().padStart(2, '0') + ':' + d.getMinutes().toString().padStart(2, '0');
}
function formatDate(ts) {
  const d = new Date(ts);
  return d.getFullYear() + '/' + (d.getMonth() + 1) + '/' + d.getDate();
}
function formatDateTime(ts) { return formatDate(ts) + ' ' + formatTime(ts); }
function showError(text) { document.getElementById('error').textContent = text; }

// ---------- 暗号処理 ----------
// 長文でも引数上限に当たらないよう、分割してbase64化する
function bytesToB64(bytes) {
  let s = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(s);
}
function b64ToBytes(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

async function getKeyFromPassphrase(passphrase, saltString) {
  const keyMaterial = await crypto.subtle.importKey('raw', te.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: te.encode(saltString), iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}
async function initCrypto() {
  const passphrase = sessionStorage.getItem('sharedPassphrase');
  const conversationKey = [myUserId, partnerUserId].sort().join('_');
  cryptoKey = await getKeyFromPassphrase(passphrase, conversationKey);
}

async function aesEncrypt(key, plain, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const params = { name: 'AES-GCM', iv };
  if (aad) params.additionalData = aad;
  const ct = new Uint8Array(await crypto.subtle.encrypt(params, key, te.encode(plain)));
  const combined = new Uint8Array(iv.length + ct.length);
  combined.set(iv, 0);
  combined.set(ct, iv.length);
  return bytesToB64(combined);
}
async function aesDecrypt(key, b64, aad) {
  const combined = b64ToBytes(b64);
  const params = { name: 'AES-GCM', iv: combined.slice(0, 12) };
  if (aad) params.additionalData = aad;
  const dec = await crypto.subtle.decrypt(params, key, combined.slice(12));
  return td.decode(dec);
}

// AAD：暗号文を別の行・別の項目へ移植しても復号が通らないようにする
function aadFor(field, m) {
  return te.encode(['v2', field, m.id, m.sender_id, m.receiver_id]
    .map(x => String(x).toLowerCase()).join('|'));
}
async function encryptField(plain, field, m) {
  return FORMAT_PREFIX + await aesEncrypt(cryptoKey, plain, aadFor(field, m));
}
async function decryptField(stored, field, m) {
  try {
    if (stored.startsWith(FORMAT_PREFIX)) {
      return await aesDecrypt(cryptoKey, stored.slice(FORMAT_PREFIX.length), aadFor(field, m));
    }
    if (Date.parse(m.created_at) < LEGACY_CUTOFF_MS) {
      return await aesDecrypt(cryptoKey, stored, null);
    }
    return DECRYPT_ERROR;
  } catch (e) {
    return DECRYPT_ERROR;
  }
}

// 動画一覧コメント用の暗号化（index.html から利用）。暗号化キーを入力するまで使えない
window.memoVault = {
  ready: false,
  async encrypt(plain, ctx) { return aesEncrypt(vaultKey, plain, te.encode('v1|comment|' + ctx)); },
  async decrypt(b64, ctx) { return aesDecrypt(vaultKey, b64, te.encode('v1|comment|' + ctx)); }
};
async function initVault() {
  const passphrase = sessionStorage.getItem('sharedPassphrase');
  vaultKey = await getKeyFromPassphrase(passphrase, 'memo-comments-v1');
  window.memoVault.ready = true;
  window.dispatchEvent(new Event('memo-vault-ready'));
}

// ---------- 端末リンク処理 ----------
async function sha256Hex(text) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', te.encode(text));
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

let lastRoomKey = null;

async function submitRoomPassphrase() {
  const val = document.getElementById('room-passphrase-input').value.trim();
  if (!val) return;
  const statusEl = document.getElementById('room-status');
  const resetBtn = document.getElementById('room-reset-btn');
  resetBtn.style.display = 'none';
  statusEl.textContent = '接続中...';

  const roomKey = await sha256Hex('room:' + val);
  lastRoomKey = roomKey;

  const { data, error } = await sb.rpc('join_group', { p_room_key: roomKey });
  if (error) {
    if (error.message.includes('room_full')) {
      statusEl.textContent = 'このルームは既に満室です（テスト等で誤って埋まった可能性があります）';
      resetBtn.style.display = 'inline-block';
    } else {
      showError('同期エラー: ' + error.message);
    }
    return;
  }

  const result = Array.isArray(data) ? data[0] : data;
  if (result.is_waiting) {
    statusEl.textContent = '相手の接続を待っています...';
    subscribeRoomWait(roomKey);
  } else {
    await onRoomConnected(result.partner_id);
  }
}

document.getElementById('room-reset-btn').addEventListener('click', async () => {
  const statusEl = document.getElementById('room-status');
  const resetBtn = document.getElementById('room-reset-btn');
  if (!lastRoomKey) return;
  statusEl.textContent = 'リセット中...';

  const { error } = await sb.rpc('reset_group', { p_room_key: lastRoomKey });
  if (error) {
    statusEl.textContent = 'リセット失敗（このルームの参加者ではない可能性があります）: ' + error.message;
    return;
  }

  resetBtn.style.display = 'none';
  statusEl.textContent = 'リセット完了。もう一度「参加」を押してください。';
});

// groups は SELECT 不可で Realtime 通知が届かないため、3秒ごとに join_group で確認する
// 10分で打ち切り（再度「参加」で再開できる）
function subscribeRoomWait(roomKey) {
  clearInterval(roomPollTimer);
  const waitStartedAt = Date.now();
  roomPollTimer = setInterval(async () => {
    if (Date.now() - waitStartedAt > 10 * 60 * 1000) {
      clearInterval(roomPollTimer);
      document.getElementById('room-status').textContent =
        '待機がタイムアウトしました。もう一度「参加」を押してください。';
      return;
    }
    const { data, error } = await sb.rpc('join_group', { p_room_key: roomKey });
    if (error) return;
    const r = Array.isArray(data) ? data[0] : data;
    if (r && !r.is_waiting && r.partner_id) {
      clearInterval(roomPollTimer);
      await onRoomConnected(r.partner_id);
    }
  }, 3000);
}

async function onRoomConnected(partnerId) {
  partnerUserId = partnerId;
  localStorage.setItem('partnerUserId', partnerUserId);
  document.getElementById('room-setup').style.display = 'none';
  await registerParticipantPair();
  checkPassphrase();
}

// ---------- 初期化 ----------
async function initAuth() {
  const { data: { session } } = await sb.auth.getSession();
  if (session) {
    myUserId = session.user.id;
  } else {
    const { data, error } = await sb.auth.signInAnonymously();
    if (error) { showError('認証エラー: ' + error.message); return; }
    myUserId = data.user.id;
  }
  document.getElementById('my-id').textContent = myUserId;

  if (!partnerUserId) {
    document.getElementById('room-setup').style.display = 'block';
  } else {
    checkPassphrase();
  }
}

// 既に links にあれば登録しない（INSERT のみ。重複エラー 23505 は無視）
async function registerParticipantPair() {
  const key = [myUserId, partnerUserId].sort().join('_');
  const { data: existing, error: e1 } = await sb.from('links')
    .select('conversation_key').eq('conversation_key', key).maybeSingle();
  if (e1) { showError('リンク確認エラー: ' + e1.message); return; }
  if (existing) return;
  const { error } = await sb.from('links').insert({
    conversation_key: key,
    user_id_1: myUserId,
    user_id_2: partnerUserId
  });
  if (error && error.code !== '23505') showError('リンク登録エラー: ' + error.message);
}

document.getElementById('room-passphrase-submit').addEventListener('click', submitRoomPassphrase);

document.getElementById('partner-submit').addEventListener('click', async () => {
  const val = document.getElementById('partner-input').value.trim();
  if (!val) return;
  partnerUserId = val;
  localStorage.setItem('partnerUserId', partnerUserId);
  document.getElementById('partner-setup').style.display = 'none';
  await registerParticipantPair();
  checkPassphrase();
});

function checkPassphrase() {
  if (!sessionStorage.getItem('sharedPassphrase')) {
    document.getElementById('passphrase-setup').style.display = 'block';
  } else {
    startChat();
  }
}
document.getElementById('passphrase-submit').addEventListener('click', () => {
  const val = document.getElementById('passphrase-input').value.trim();
  if (!val) return;
  sessionStorage.setItem('sharedPassphrase', val);
  document.getElementById('passphrase-setup').style.display = 'none';
  startChat();
});

document.getElementById('reset-partner').addEventListener('click', () => {
  localStorage.removeItem('partnerUserId');
  sessionStorage.removeItem('sharedPassphrase');
  location.reload();
});

async function startChat() {
  await registerParticipantPair();
  await initCrypto();
  await initVault();
  await loadMessages();
  subscribeMessages();
  subscribeTyping();
  subscribePresence();
  markIncomingAsRead();
  logAccess();
  updateMyStatus();
  loadPartnerLastSeen();
  setInterval(updateMyStatus, 20000);
}

// ---------- 同期状態 ----------
async function updateMyStatus() {
  await sb.from('device_status').upsert({ user_id: myUserId, last_seen: new Date().toISOString() });
}
async function loadPartnerLastSeen() {
  const { data } = await sb.from('device_status').select('last_seen').eq('user_id', partnerUserId).maybeSingle();
  if (data) partnerLastSeen = data.last_seen;
  updateOnlineStatusUI();
}
function updateOnlineStatusUI() {
  const el = document.getElementById('partner-status');
  if (partnerOnline) {
    el.textContent = '端末B: オンライン';
  } else {
    el.textContent = partnerLastSeen ? '端末B: 最終同期 ' + formatDateTime(partnerLastSeen) : '端末B: 未同期';
  }
}
function subscribePresence() {
  presenceChannel = sb.channel('presence-' + [myUserId, partnerUserId].sort().join('-'), {
    config: { presence: { key: myUserId } }
  });
  presenceChannel
    .on('presence', { event: 'sync' }, () => {
      const state = presenceChannel.presenceState();
      const wasOnline = partnerOnline;
      partnerOnline = Object.keys(state).includes(partnerUserId);
      if (wasOnline && !partnerOnline) loadPartnerLastSeen();
      updateOnlineStatusUI();
    })
    .subscribe(async (status) => {
      if (status === 'SUBSCRIBED') await presenceChannel.track({ online_at: new Date().toISOString() });
    });
}

// ---------- 履歴 ----------
async function logAccess() {
  await sb.from('sync_logs').insert({ user_id: myUserId, event_type: 'login' });
}
async function loadAccessLogs() {
  const { data, error } = await sb.from('sync_logs')
    .select('*').in('user_id', [myUserId, partnerUserId])
    .order('created_at', { ascending: false })
    .limit(50);
  const panel = document.getElementById('access-log-panel');
  if (error) { panel.textContent = 'ログ取得エラー: ' + error.message; return; }
  panel.innerHTML = '';
  data.forEach(log => {
    const line = document.createElement('div');
    const who = log.user_id === myUserId ? '端末A' : '端末B';
    line.textContent = formatDateTime(log.created_at) + ' - ' + who + ' - ' + log.event_type;
    panel.appendChild(line);
  });
}
document.getElementById('toggle-log').addEventListener('click', async () => {
  logVisible = !logVisible;
  const panel = document.getElementById('access-log-panel');
  panel.style.display = logVisible ? 'block' : 'none';
  if (logVisible) await loadAccessLogs();
});

// ---------- データ読み込み/購読 ----------
async function loadMessages() {
  const { data, error } = await sb
    .from('items')
    .select('*')
    .or(`and(sender_id.eq.${myUserId},receiver_id.eq.${partnerUserId}),and(sender_id.eq.${partnerUserId},receiver_id.eq.${myUserId})`)
    .order('created_at', { ascending: true });

  if (error) { showError('読み込みエラー: ' + error.message); return; }
  allMessages = data;
  renderAll();
}

function isRelevant(msg) {
  return (msg.sender_id === myUserId && msg.receiver_id === partnerUserId) ||
         (msg.sender_id === partnerUserId && msg.receiver_id === myUserId);
}

// 編集中は再描画しない（入力途中の内容が消えるのを防ぐ。保存・キャンセル時に反映される）
function renderUnlessEditing() { if (!editingId) renderAll(); }

function subscribeMessages() {
  sb.channel('items-realtime')
    .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'items' }, (payload) => {
      const msg = payload.new;
      if (!isRelevant(msg)) return;
      if (allMessages.some(m => m.id === msg.id)) return;
      allMessages.push(msg);
      renderUnlessEditing();
      if (msg.sender_id === partnerUserId) markIncomingAsRead();
    })
    .on('postgres_changes', { event: 'UPDATE', schema: 'public', table: 'items' }, (payload) => {
      const msg = payload.new;
      if (!isRelevant(msg)) return;
      const idx = allMessages.findIndex(m => m.id === msg.id);
      if (idx !== -1) allMessages[idx] = msg;
      renderUnlessEditing();
    })
    .on('postgres_changes', { event: 'DELETE', schema: 'public', table: 'items' }, (payload) => {
      const id = payload.old && payload.old.id;
      if (!id || !allMessages.some(m => m.id === id)) return;
      allMessages = allMessages.filter(m => m.id !== id);
      plainCache.delete(id);
      renderUnlessEditing();
    })
    .subscribe();
}

function subscribeTyping() {
  typingChannel = sb.channel('typing-' + [myUserId, partnerUserId].sort().join('-'));
  typingChannel.on('broadcast', { event: 'typing' }, (payload) => {
    if (payload.payload.userId === partnerUserId) showTypingIndicator();
  }).subscribe();
}
function showTypingIndicator() {
  const el = document.getElementById('typing-indicator');
  el.textContent = '他の端末で編集中...';
  clearTimeout(typingTimeout);
  typingTimeout = setTimeout(() => { el.textContent = ''; }, 3000);
}
function broadcastTyping() {
  if (!typingChannel) return;
  typingChannel.send({ type: 'broadcast', event: 'typing', payload: { userId: myUserId } });
}

// 既読更新：受信者は items を直接更新できないため、mark_read RPC（security definer）を使う
async function markIncomingAsRead() {
  if (!partnerUserId) return;
  const { error } = await sb.rpc('mark_read', { p_sender: partnerUserId });
  if (error && !markReadWarned) {
    markReadWarned = true;
    showError('既読更新エラー: ' + error.message + '（mark_read のSQLが未適用の可能性）');
  }
}

async function deleteMessage(id) {
  const { data, error } = await sb.from('items').delete().eq('id', id).select();
  if (error) { showError('削除エラー: ' + error.message); return; }
  if (!data || data.length === 0) { showError('削除エラー: 権限がないか対象が見つかりません'); return; }
  allMessages = allMessages.filter(m => m.id !== id);
  plainCache.delete(id);
  renderAll();
}

async function bulkDeleteOwn() {
  if (!confirm('自分の発言をすべて削除しますか？')) return;
  const { error } = await sb.from('items').delete()
    .eq('sender_id', myUserId).eq('receiver_id', partnerUserId);
  if (error) { showError('全削除エラー: ' + error.message); return; }
  allMessages.filter(m => m.sender_id === myUserId).forEach(m => plainCache.delete(m.id));
  allMessages = allMessages.filter(m => m.sender_id !== myUserId);
  renderAll();
}
document.getElementById('bulk-delete').addEventListener('click', bulkDeleteOwn);

function startEdit(id) { editingId = id; renderAll(); }
function cancelEdit() { editingId = null; renderAll(); }

async function saveEdit(id, newPlainContent) {
  const text = newPlainContent.trim();
  if (!text) return;
  const m = allMessages.find(x => x.id === id);
  if (!m) return;
  const encrypted = await encryptField(text, 'content', m);
  const editedAt = new Date().toISOString();
  const { error } = await sb.from('items').update({ content: encrypted, edited_at: editedAt }).eq('id', id);
  if (error) { showError('編集エラー: ' + error.message); return; }
  m.content = encrypted;
  m.edited_at = editedAt;
  editingId = null;
  renderAll();
}

function setReplyTarget(id, plainContent) {
  replyTarget = { id, content: plainContent };
  document.getElementById('reply-preview-text').textContent = plainContent.slice(0, 40);
  document.getElementById('reply-preview').style.display = 'block';
}
document.getElementById('reply-cancel').addEventListener('click', () => {
  replyTarget = null;
  document.getElementById('reply-preview').style.display = 'none';
});

async function sendMessage() {
  const input = document.getElementById('input');
  const plain = input.value.trim();
  if (!plain) return;

  // AAD に行IDを含めるため、IDはクライアントで先に生成する
  const meta = { id: crypto.randomUUID(), sender_id: myUserId, receiver_id: partnerUserId };
  const payload = {
    id: meta.id,
    sender_id: meta.sender_id,
    receiver_id: meta.receiver_id,
    content: await encryptField(plain, 'content', meta)
  };
  if (replyTarget) {
    payload.reply_to_id = replyTarget.id;
    payload.reply_to_content = await encryptField(replyTarget.content.slice(0, 60), 'reply', meta);
  }

  const { error } = await sb.from('items').insert(payload);
  if (error) { showError('送信エラー: ' + error.message); return; }
  input.value = '';
  replyTarget = null;
  document.getElementById('reply-preview').style.display = 'none';
}
document.getElementById('send').addEventListener('click', sendMessage);
document.getElementById('input').addEventListener('input', broadcastTyping);
// IME変換確定のEnterでは送信しない
document.getElementById('input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.isComposing && e.keyCode !== 229) sendMessage();
});

document.getElementById('search-input').addEventListener('input', (e) => {
  searchTerm = e.target.value.trim().toLowerCase();
  renderAll();
});

function copyToClipboard(el, text) {
  navigator.clipboard.writeText(text).then(() => {
    el.classList.add('copied-flash');
    setTimeout(() => el.classList.remove('copied-flash'), 400);
  });
}
function attachLongPress(el, plainText) {
  let timer = null;
  const start = () => { timer = setTimeout(() => copyToClipboard(el, plainText), 600); };
  const cancel = () => { clearTimeout(timer); };
  el.addEventListener('pointerdown', start);
  el.addEventListener('pointerup', cancel);
  el.addEventListener('pointerleave', cancel);
  el.addEventListener('pointercancel', cancel);
}

// ---------- 描画 ----------
// 復号結果をキャッシュし、新着・変更分だけ復号する
async function decryptMessage(m) {
  const reply = m.reply_to_content || null;
  const hit = plainCache.get(m.id);
  if (hit && hit.content === m.content && hit.reply === reply) return hit;
  const entry = {
    content: m.content,
    reply: reply,
    plain: await decryptField(m.content, 'content', m),
    replyPlain: reply ? await decryptField(reply, 'reply', m) : null
  };
  plainCache.set(m.id, entry);
  return entry;
}

async function renderAll() {
  const seq = ++renderSeq;
  const entries = await Promise.all(allMessages.map(async m => ({ m, d: await decryptMessage(m) })));
  if (seq !== renderSeq) return; // 新しい描画要求が来ていれば、古い結果は捨てる

  const visible = searchTerm
    ? entries.filter(e => e.d.plain.toLowerCase().includes(searchTerm))
    : entries;

  const chat = document.getElementById('chat');
  chat.innerHTML = '';
  let lastDate = null;
  visible.forEach(e => {
    const msg = Object.assign({}, e.m, { _plain: e.d.plain, _replyPlain: e.d.replyPlain });
    const dateStr = formatDate(msg.created_at);
    if (dateStr !== lastDate) {
      const sep = document.createElement('div');
      sep.className = 'date-sep';
      sep.textContent = dateStr;
      chat.appendChild(sep);
      lastDate = dateStr;
    }
    chat.appendChild(buildMessageElement(msg));
  });
}

function buildMessageElement(msg) {
  const isMine = msg.sender_id === myUserId;
  const div = document.createElement('div');
  div.className = 'msg' + (isMine ? ' mine' : '');
  div.id = 'msg-' + msg.id;

  if (msg._replyPlain) {
    const quote = document.createElement('div');
    quote.className = 'msg-quote';
    quote.textContent = '↩ ' + msg._replyPlain;
    div.appendChild(quote);
  }

  if (editingId === msg.id) {
    const editInput = document.createElement('input');
    editInput.type = 'text';
    editInput.value = msg._plain;
    const saveBtn = document.createElement('button');
    saveBtn.textContent = '保存';
    saveBtn.addEventListener('click', () => saveEdit(msg.id, editInput.value));
    const cancelBtn = document.createElement('button');
    cancelBtn.textContent = 'キャンセル';
    cancelBtn.addEventListener('click', cancelEdit);
    div.appendChild(editInput);
    div.appendChild(saveBtn);
    div.appendChild(cancelBtn);
    return div;
  }

  const textSpan = document.createElement('span');
  textSpan.textContent = msg._plain;
  div.appendChild(textSpan);
  attachLongPress(textSpan, msg._plain);

  const meta = document.createElement('span');
  meta.className = 'msg-meta';
  let metaText = formatTime(msg.created_at);
  if (msg.edited_at) metaText += ' (編集済み)';
  if (isMine) metaText += msg.read_at ? ' 既読' : ' 未読';
  meta.textContent = metaText;
  div.appendChild(meta);

  const replyBtn = document.createElement('span');
  replyBtn.className = 'msg-action';
  replyBtn.textContent = '[返信]';
  replyBtn.addEventListener('click', () => setReplyTarget(msg.id, msg._plain));
  div.appendChild(replyBtn);

  if (isMine) {
    const editBtn = document.createElement('span');
    editBtn.className = 'msg-action';
    editBtn.textContent = '[編集]';
    editBtn.addEventListener('click', () => startEdit(msg.id));
    div.appendChild(editBtn);

    const delBtn = document.createElement('span');
    delBtn.className = 'msg-action danger';
    delBtn.textContent = '[削除]';
    delBtn.addEventListener('click', () => deleteMessage(msg.id));
    div.appendChild(delBtn);
  }

  return div;
}

// ===== 起動（招待コードのゲートは廃止。防御は RLS と暗号化キーが担う） =====
initAuth();
// ===== END OF main.js =====
