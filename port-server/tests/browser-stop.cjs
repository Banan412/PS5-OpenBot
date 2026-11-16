// Host-only stop-control journey using an isolated slow mock model. Run from repository root after building app and server.
const { chromium } = require('playwright-core');
const { spawn } = require('child_process');
const fs = require('fs'); const os = require('os'); const path = require('path');
const crypto = require('crypto'); const net = require('net'); const http = require('http');
(async () => {
  const mock = http.createServer((req, res) => {
    req.resume(); req.on('end', () => {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write('data: {"choices":[{"index":0,"delta":{"content":"A partial answer"},"finish_reason":null}]}\n\n');
      res.on('close', () => { globalThis.modelClosed = true; });
    });
  });
  await new Promise(resolve => mock.listen(0, '127.0.0.1', resolve));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'openbot-browser-'));
  const secret = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(path.join(dir, 'secret'), secret);
  const probe = net.createServer(); await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
  const port = probe.address().port; await new Promise(resolve => probe.close(resolve));
  const origin = `http://127.0.0.1:${port}`;
  const modelUrl = `http://127.0.0.1:${mock.address().port}/v1`;
  const modelId = 'mock';
  const processHandle = spawn(path.resolve('port-server/target/debug/openbot-port-server.exe'), [], {
    cwd: path.resolve('port-server'), stdio: 'ignore', env: { ...process.env,
      OPENBOT_BIND: `127.0.0.1:${port}`, OPENBOT_ALLOWED_ORIGIN: 'auto',
      OPENBOT_DB_PATH: path.join(dir, 'db'), OPENBOT_SETUP_TOKEN_FILE: path.join(dir, 'secret'),
      OPENBOT_MODEL_URL: modelUrl, OPENBOT_MODEL_ID: modelId }
  });
  let browser; let page; const failures = [];
  try {
    let started = false;
    for (let n = 0; n < 100; n++) { try { await fetch(origin + '/healthz'); started = true; break; } catch { await new Promise(r => setTimeout(r, 100)); } }
    if (!started) throw Error('Host server did not start');
    browser = await chromium.launch({headless: true, executablePath: process.env.CHROME_PATH || 'C:/Program Files/Google/Chrome/Application/chrome.exe'});
    const context = await browser.newContext(); page = await context.newPage();
    page.on('response', r => { if (r.url().startsWith(origin + '/api/') && r.status() >= 400) failures.push(`${r.status()} ${new URL(r.url()).pathname}`); });
    await page.goto(origin + '/sign'); await page.locator('#local-name').waitFor({timeout: 20000});
    await page.locator('#local-name').fill('Owner'); await page.locator('#local-email').fill('owner@example.test');
    await page.locator('#local-password').fill(crypto.randomBytes(24).toString('hex')); await page.locator('#local-setup-code').fill(secret);
    await page.getByRole('button', {name:'Create administrator'}).click(); await page.waitForURL(origin + '/', {timeout:15000});
    const response = await context.request.post(origin + '/api/v2/organizations/default/bots', {headers:{Origin:origin,'Idempotency-Key':'ui-bot'},data:{name:'Helper',title:'',roleDescription:'Be helpful',visibility:'private'}});
    if (response.status() !== 201) throw Error('Bot creation failed: ' + response.status());
    const bot = (await response.json()).bot.id; await page.goto(origin + '/bot?agent=' + encodeURIComponent(bot));
    const input = page.getByPlaceholder('Type a message...'); await input.waitFor({timeout:20000}); await input.fill('Tell me a story'); await input.press('Enter');
    await page.getByText('A partial answer', {exact:false}).first().waitFor({timeout:20000}); console.log('Partial response visible');
    const stop = page.waitForResponse(r => /\/api\/copilotkit\/agent\/[^/]+\/stop\//.test(new URL(r.url()).pathname), {timeout:10000});
    await page.getByRole('button', {name:'Stop', exact:true}).click({timeout:8000}); console.log('Stop clicked');
    const stopResponse = await stop; console.log('Stop HTTP status:',stopResponse.status());
    if (stopResponse.status() !== 200) throw Error('Stop endpoint returned ' + stopResponse.status());
    // The SDK aborts its fetch while stopping; inspect durable state instead of waiting for its response body.
    const {execFileSync} = require('child_process');
    let recorded = false;
    for (let n=0; n<100 && !recorded; n++) {
      const state = execFileSync('python', ['-c', 'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute(\"select count(*) from port_runs r join port_run_events e on e.conversation_id=r.conversation_id where r.status=\'failed\' and json_extract(e.event_json,\'$.type\')=\'RUN_ERROR\' and json_extract(e.event_json,\'$.code\')=\'STOPPED\'\").fetchone()[0])', path.join(dir,'db')], {encoding:'utf8'}).trim();
      recorded = state === '1'; if (!recorded) await new Promise(r=>setTimeout(r,50));
    }
    if (!recorded) throw Error('Stopped run was not persisted'); console.log('Stopped run persisted');
    for (let n=0; n<100 && !globalThis.modelClosed; n++) await new Promise(r=>setTimeout(r,50));
    if (!globalThis.modelClosed) throw Error('Model connection did not close'); console.log('Model connection closed');
    console.log('Reloading'); await page.reload({timeout:10000});
    await page.getByText('A partial answer', {exact:false}).first().waitFor({timeout:20000});
    console.log('PASS: Stop canceled the model request and retained the partial response after reload.');
    console.log('Other API responses:', JSON.stringify([...new Set(failures)]));
  } catch (error) {
    console.error('Browser check failed:', error.message);
    if (page) console.error('Visible page:', (await page.locator('body').innerText()).slice(0,1600));
    console.error('API responses:', JSON.stringify([...new Set(failures)])); process.exitCode = 1;
  } finally {
    if (browser) await browser.close();
    if (processHandle.exitCode === null) { processHandle.kill(); await new Promise(r => processHandle.once('exit', r)); }
    mock.closeAllConnections(); mock.close();
    const resolved = fs.realpathSync(dir);
    const tempRoot = fs.realpathSync(os.tmpdir()) + path.sep;
    if (!resolved.toLowerCase().startsWith(tempRoot.toLowerCase()) || !path.basename(resolved).startsWith('openbot-browser-')) {
      throw Error('Refusing to remove unexpected temporary directory');
    }
    fs.rmSync(resolved, {recursive:true, force:true});
  }
})().catch(e => { console.error(e.message); process.exitCode=1; });
