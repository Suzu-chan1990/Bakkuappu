/* Bakkuappu admin: start jobs, live status, restore dialog */
(function () {
    'use strict';
    const cfg = window.BakkuappuAdmin || {};
    const consoleEl = document.getElementById('bkp-console');
    const statusEl = document.getElementById('bkp-job-status');
    const titleEl = document.getElementById('bkp-job-title');
    const startButtons = Array.from(document.querySelectorAll('.bkp-start, .bkp-restore, .bkp-verify'));
    const isHexKey = v => /^[0-9a-fA-F]{64}$/.test(v.trim());
    let wasRunning = false;
    let timer = null;

    const kinds = { backup: 'Backup', restore: 'Restore', verify: 'Verification' };
    const states = { running: ['bkp-pill-run', 'Running'], done: ['bkp-pill-ok', 'Successful'], error: ['bkp-pill-bad', 'Error'], aborted: ['bkp-pill-bad', 'Aborted'] };

    function post(params) {
        const data = new FormData();
        Object.keys(params).forEach(k => data.append(k, params[k]));
        data.append('nonce', cfg.nonce);
        return fetch(cfg.ajax, { method: 'POST', body: data, credentials: 'same-origin' }).then(async res => {
            const text = await res.text();
            try { return JSON.parse(text); }
            catch (e) {
                // Not JSON (PHP error page, blocked request ...): show status and the start of the answer
                const snippet = text.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 300);
                throw new Error('HTTP ' + res.status + (snippet ? ': ' + snippet : ''));
            }
        });
    }

    function setButtons(disabled) {
        startButtons.forEach(b => { if (!b.dataset.keyMissing) b.disabled = disabled; });
    }

    function append(text) {
        if (!consoleEl) return;
        consoleEl.textContent += (consoleEl.textContent ? '\n' : '') + '> ' + text;
        consoleEl.scrollTop = consoleEl.scrollHeight;
    }

    function render(data) {
        if (!statusEl || !consoleEl) return;
        const job = data.job;
        if (!job) {
            statusEl.className = 'bkp-pill';
            statusEl.textContent = '–';
            titleEl.textContent = 'No job has run yet.';
            if (!consoleEl.textContent) consoleEl.textContent = '> System ready.';
            return;
        }
        const st = states[job.status] || ['bkp-pill', job.status];
        statusEl.className = 'bkp-pill ' + st[0];
        statusEl.textContent = st[1];
        titleEl.textContent = (kinds[job.kind] || job.kind) + ' · ' + job.detail + ' · ' + job.started;
        consoleEl.textContent = job.lines.join('\n') + (job.summary && job.status !== 'running' ? '\n\n' + job.summary : '');
        consoleEl.scrollTop = consoleEl.scrollHeight;
    }

    function poll() {
        post({ action: 'bakkuappu_status' }).then(res => {
            if (!res.success) return;
            render(res.data);
            setButtons(res.data.running);
            if (wasRunning && !res.data.running && document.querySelector('.bkp-table, .bkp-kv')) {
                // A job just finished: reload so the list and the status show the new state
                setTimeout(() => window.location.reload(), 1500);
            }
            wasRunning = res.data.running;
            clearTimeout(timer);
            timer = setTimeout(poll, res.data.running ? 2000 : 8000);
        }).catch(err => {
            append('Status could not be loaded (' + err.message + ')');
            clearTimeout(timer);
            timer = setTimeout(poll, 10000);
        });
    }

    function start(params) {
        setButtons(true);
        append('Starting …');
        post(Object.assign({ action: 'bakkuappu_start' }, params)).then(res => {
            const msg = (res.data && res.data.message) || 'Unknown response';
            append(res.success ? msg : 'Error: ' + msg);
            if (!res.success) setButtons(false);
            wasRunning = res.success;
            clearTimeout(timer);
            timer = setTimeout(poll, 1500);
        }).catch(err => {
            append('Connection error to the server (' + err.message + ')');
            setButtons(false);
        });
    }

    startButtons.forEach(b => { if (b.disabled) b.dataset.keyMissing = '1'; });

    document.querySelectorAll('.bkp-start').forEach(btn => {
        btn.addEventListener('click', () => start({ kind: btn.dataset.kind, type: btn.dataset.type || '', file: btn.dataset.file || '' }));
    });

    // Verify: backups made with the public key need the private key first
    const pkModal = document.getElementById('bkp-pk-modal');
    let pkFile = '';
    document.querySelectorAll('.bkp-verify').forEach(btn => {
        btn.addEventListener('click', () => {
            if (btn.dataset.sealed && pkModal) {
                pkFile = btn.dataset.file;
                document.getElementById('bkp-pk-input').value = '';
                pkModal.hidden = false;
                document.getElementById('bkp-pk-input').focus();
                return;
            }
            start({ kind: 'verify', file: btn.dataset.file });
        });
    });
    if (pkModal) {
        const input = document.getElementById('bkp-pk-input');
        const close = () => { pkModal.hidden = true; input.value = ''; };
        document.getElementById('bkp-pk-cancel').addEventListener('click', close);
        pkModal.addEventListener('click', e => { if (e.target === pkModal) close(); });
        document.getElementById('bkp-pk-go').addEventListener('click', () => {
            if (!isHexKey(input.value)) { alert('The private key must have 64 hex characters.'); return; }
            const key = input.value.trim();
            close();
            start({ kind: 'verify', file: pkFile, private_key: key });
        });
    }

    // Restore dialog
    const modal = document.getElementById('bkp-restore-modal');
    if (modal) {
        const what = document.getElementById('bkp-restore-what');
        const safety = document.getElementById('bkp-restore-safety');
        const confirmBox = document.getElementById('bkp-restore-confirm');
        const go = document.getElementById('bkp-restore-go');
        const siteBox = document.getElementById('bkp-restore-site');
        const pkBox = document.getElementById('bkp-restore-pk');
        const pkInput = document.getElementById('bkp-restore-pk-input');
        let file = '';
        let sealed = false;
        const update = () => { go.disabled = !confirmBox.checked || (sealed && !isHexKey(pkInput.value)); };
        document.querySelectorAll('.bkp-restore').forEach(btn => {
            btn.addEventListener('click', () => {
                file = btn.dataset.file;
                sealed = !!btn.dataset.sealed;
                what.textContent = btn.dataset.label + ' (' + file + ')';
                siteBox.hidden = !btn.dataset.site;
                siteBox.textContent = btn.dataset.site ? 'Warning: this backup comes from ' + btn.dataset.site + ', not from this website. URLs are not changed when restoring.' : '';
                pkBox.hidden = !sealed;
                pkInput.value = '';
                safety.checked = true;
                confirmBox.checked = false;
                update();
                modal.hidden = false;
            });
        });
        confirmBox.addEventListener('change', update);
        pkInput.addEventListener('input', update);
        const close = () => { modal.hidden = true; pkInput.value = ''; };
        document.getElementById('bkp-restore-cancel').addEventListener('click', close);
        modal.addEventListener('click', e => { if (e.target === modal) close(); });
        go.addEventListener('click', () => {
            const params = { kind: 'restore', file: file, safety: safety.checked ? '1' : '' };
            if (sealed) params.private_key = pkInput.value.trim();
            close();
            start(params);
        });
    }

    if (consoleEl) poll();
})();
