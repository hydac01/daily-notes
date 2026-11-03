const SUPABASE_URL = "https://vshprfqrpicimjboiwjt.supabase.co";
const SUPABASE_ANON_KEY = "sb_publishable_X8UkIz_-yKic4cxHC0_QQw_5EojlmIa";
const sb = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

let myUserId = null;
let partnerUserId = localStorage.getItem('partnerUserId');
if (partnerUserId === 'null' || partnerUserId === '') partnerUserId = null;

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
let logVisible = false;
let roomWaitChannel = null;
let roomPollTimer = null;

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

// ---------- データ処理 ----------
async function getKeyFromPassphrase(passphrase, saltString) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode(saltString), iterations: 100000, hash: 'SHA-256' },
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
async function encryptText(plain) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, enc.encode(plain));
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);
  return btoa(String.fromCharCode(...combined));
}
async function decryptText(b64) {
  try {
    const combined = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const iv = combined.slice(0, 12);
    const data = combined.slice(12);
    const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, data);
    return new TextDecoder().decode(dec);
  } catch (e) {
    return '[復号エラー：合言葉不一致または未暗号化データ]';
  }
}

// ---------- 端末リンク処理 ----------
async function sha256Hex(text) {
  const enc = new TextEncoder();
  const data = enc.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
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

// 変更点：Realtime通知（groupsはSELECT不可で届かない）をやめ、3秒ごとにjoin_groupで確認
function subscribeRoomWait(roomKey) {
  clearInterval(roomPollTimer);
  roomPollTimer = setInterval(async () => {
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

// 変更点：既にlinksにあればupsertしない（INSERTのみ。重複エラー23505は無視）
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
  const val = document.getElementById('passphrase-input').value;
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

function subscribeMessages() {
  sb.channel('items-realtime')
    .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'items' }, (payload) => {
      const msg = payload.new;
      if (!isRelevant(msg)) return;
      allMessages.push(msg);
      renderAll();
      if (msg.sender_id === partnerUserId) markIncomingAsRead();
    })
    .on('postgres_changes', { event: 'UPDATE', schema: 'public', table: 'items' }, (payload) => {
      const msg = payload.new;
      if (!isRelevant(msg)) return;
      const idx = allMessages.findIndex(m => m.id === msg.id);
      if (idx !== -1) allMessages[idx] = msg;
      renderAll();
    })
    .on('postgres_changes', { event: 'DELETE', schema: 'public', table: 'items' }, (payload) => {
      allMessages = allMessages.filter(m => m.id !== payload.old.id);
      renderAll();
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

async function markIncomingAsRead() {
  await sb.from('items').update({ read_at: new Date().toISOString() })
    .eq('receiver_id', myUserId).eq('sender_id', partnerUserId)
    .is('read_at', null);
}

async function deleteMessage(id) {
  const { data, error } = await sb.from('items').delete().eq('id', id).select();
  if (error) { showError('削除エラー: ' + error.message); return; }
  if (!data || data.length === 0) { showError('削除エラー: 権限がないか対象が見つかりません'); return; }
  allMessages = allMessages.filter(m => m.id !== id);
  renderAll();
}

async function bulkDeleteOwn() {
  if (!confirm('自分の発言をすべて削除しますか？')) return;
  const { error } = await sb.from('items').delete()
    .eq('sender_id', myUserId).eq('receiver_id', partnerUserId);
  if (error) { showError('全削除エラー: ' + error.message); return; }
  allMessages = allMessages.filter(m => m.sender_id !== myUserId);
  renderAll();
}
document.getElementById('bulk-delete').addEventListener('click', bulkDeleteOwn);

function startEdit(id) { editingId = id; renderAll(); }
function cancelEdit() { editingId = null; renderAll(); }

async function saveEdit(id, newPlainContent) {
  if (!newPlainContent.trim()) return;
  const encrypted = await encryptText(newPlainContent.trim());
  const { error } = await sb.from('items').update({
    content: encrypted, edited_at: new Date().toISOString()
  }).eq('id', id);
  if (error) { showError('編集エラー: ' + error.message); return; }
  editingId = null;
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

  const encryptedContent = await encryptText(plain);
  const payload = { sender_id: myUserId, receiver_id: partnerUserId, content: encryptedContent };
  if (replyTarget) {
    payload.reply_to_id = replyTarget.id;
    payload.reply_to_content = await encryptText(replyTarget.content.slice(0, 60));
  }

  const { error } = await sb.from('items').insert(payload);
  if (error) { showError('送信エラー: ' + error.message); return; }
  input.value = '';
  replyTarget = null;
  document.getElementById('reply-preview').style.display = 'none';
}
document.getElementById('send').addEventListener('click', sendMessage);
document.getElementById('input').addEventListener('input', broadcastTyping);
document.getElementById('input').addEventListener('keydown', (e) => { if (e.key === 'Enter') sendMessage(); });

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
}

// ---------- 描画 ----------
async function renderAll() {
  const chat = document.getElementById('chat');

  const list = searchTerm
    ? allMessages.filter(m => true)
    : allMessages;

  const decrypted = await Promise.all(list.map(async m => ({
    ...m,
    _plain: await decryptText(m.content),
    _replyPlain: m.reply_to_content ? await decryptText(m.reply_to_content) : null
  })));

  const filtered = searchTerm
    ? decrypted.filter(m => m._plain.toLowerCase().includes(searchTerm))
    : decrypted;

  chat.innerHTML = '';
  let lastDate = null;
  filtered.forEach(msg => {
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
