// Exercise the real offline document through Chromium's DevTools protocol.
// Node 22 provides WebSocket; no browser automation dependency is required.
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const [chrome, report, output] = process.argv.slice(2);
let child, socket;
const pending = new Map();
let serial = 0;
const errors = [], requests = [];
let lastCommand = "launch";
const watchdog = setTimeout(() => {
  console.error(`Browser validation timed out during ${lastCommand}`);
  if (child) child.kill();
  process.exit(1);
}, 60000);

async function main() {
  const endpoint = await new Promise((resolve, reject) => {
    child = spawn(chrome, ["--headless", "--remote-debugging-port=0", "--no-first-run",
      "--no-default-browser-check", "--disable-background-networking", "--disable-extensions",
      `--user-data-dir=${path.join(output, "browser-profile")}`, "about:blank"],
      { windowsHide: true, stdio: ["ignore", "ignore", "pipe"] });
    let log = "";
    child.stderr.on("data", data => {
      log += data.toString();
      const match = log.match(/DevTools listening on (ws:\/\/\S+)/);
      if (match) resolve(match[1]);
    });
    child.on("error", reject);
    child.on("exit", code => reject(new Error(`Browser exited ${code}: ${log}`)));
  });
  socket = new WebSocket(endpoint);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });
  socket.addEventListener("message", event => {
    const message = JSON.parse(event.data);
    if (message.id) {
      const handlers = pending.get(message.id);
      pending.delete(message.id);
      if (message.error) handlers.reject(new Error(JSON.stringify(message.error)));
      else handlers.resolve(message.result);
    } else if (message.method === "Runtime.exceptionThrown") {
      errors.push(message.params.exceptionDetails.text);
    } else if (message.method === "Network.requestWillBeSent") {
      requests.push(message.params.request.url);
    }
  });
  socket.addEventListener("close", () => {
    pending.forEach(({ reject }) => reject(new Error(`Browser connection closed during ${lastCommand}`)));
    pending.clear();
  });
  function send(method, params = {}, sessionId) {
    return new Promise((resolve, reject) => {
      const id = ++serial;
      lastCommand = method;
      pending.set(id, { resolve, reject });
      socket.send(JSON.stringify({ id, method, params, sessionId }));
    });
  }
  const { targetId } = await send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
  const command = (method, params) => send(method, params, sessionId);
  async function evaluate(expression) {
    const result = await command("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result.value;
  }
  async function until(expression) {
    for (let i = 0; i < 200; i++) {
      if (await evaluate(expression)) return;
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw new Error(`Timed out: ${expression}`);
  }
  await command("Runtime.enable");
  await command("Network.enable");
  await command("Page.enable");
  await command("Emulation.setDeviceMetricsOverride", { width: 1440, height: 1050, deviceScaleFactor: 1, mobile: false });
  await command("Page.navigate", { url: pathToFileURL(path.resolve(report)).href });
  await until('document.readyState === "complete" && !document.querySelector(".report-tools").hidden');
  await evaluate('typeof diagramWork !== "undefined" ? diagramWork : Promise.resolve()');
  assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true, "desktop overflow");
  const screenshot = await command("Page.captureScreenshot", { format: "png" });
  fs.writeFileSync(path.join(output, "report-desktop.png"), Buffer.from(screenshot.data, "base64"));
  await evaluate(`document.querySelectorAll("details.sec").forEach(d => d.open = false);
    document.getElementById("report-search").value = "vm-ghost";
    document.getElementById("report-search").dispatchEvent(new Event("input"));`);
  assert.equal(await evaluate('Array.from(document.querySelectorAll("details.inv tr")).some(r => !r.hidden && r.textContent.includes("vm-ghost") && r.getBoundingClientRect().height > 0)'), true, "search reveals nested evidence");
  await evaluate('document.getElementById("clear-filters").click()');
  assert.equal(await evaluate('Array.from(document.querySelectorAll("details.sec")).every(d => !d.open)'), true, "search restores collapsed state");
  await evaluate(`document.getElementById("filter-severity").value = "critical";
    document.getElementById("filter-severity").dispatchEvent(new Event("input"));`);
  assert.equal(await evaluate('Array.from(document.querySelectorAll(".finding")).filter(c => !c.hidden).every(c => c.dataset.severity === "critical")'), true);
  await evaluate('document.querySelector(\'a[href="#CAT-001"]\').click()');
  assert.equal(await evaluate('!document.getElementById("CAT-001").hidden'), true, "evidence link clears conflicting filters");
  await evaluate(`document.getElementById("filter-project").value = "Platform";
    document.getElementById("filter-project").dispatchEvent(new Event("input"));`);
  assert.equal(await evaluate('Array.from(document.querySelectorAll(".finding")).filter(c => !c.hidden).every(c => JSON.parse(c.dataset.projects).includes("Platform"))'), true);
  await evaluate('document.getElementById("clear-filters").click()');
  await evaluate(`const inventory = Array.from(document.querySelectorAll("details.inv")).find(d => d.querySelector("summary").textContent.includes("Catalog Items and Deployment Usage"));
    window.catalogTable = inventory.querySelector("table");
    catalogTable.querySelectorAll(".sort-button")[5].click();`);
  const counts = await evaluate('Array.from(catalogTable.tBodies[0].rows).map(r => Number(r.cells[5].textContent))');
  assert.deepEqual(counts, [...counts].sort((a, b) => a - b));
  // Full printing includes all evidence regardless of active filters, then restores them.
  await evaluate(`document.getElementById("filter-severity").value = "critical";
    document.getElementById("filter-severity").dispatchEvent(new Event("input"));
    window.print = () => { window.printProof = {
      allVisible: Array.from(document.querySelectorAll(".finding")).every(c => !c.hidden),
      allOpen: Array.from(document.querySelectorAll("details")).every(d => d.open),
      summary: document.body.classList.contains("print-summary"),
      rendered: document.querySelectorAll("pre.mermaid svg").length
    }; window.dispatchEvent(new Event("afterprint")); };
    document.getElementById("print-full").click();`);
  await until('Boolean(window.printProof)');
  const proof = await evaluate('window.printProof');
  assert.equal(proof.allVisible, true);
  assert.equal(proof.allOpen, true);
  assert.equal(proof.summary, false);
  assert.ok(proof.rendered > 0, "diagrams render before print");
  assert.equal(await evaluate('document.querySelectorAll(".finding[hidden]").length > 0'), true);
  await evaluate('window.printProof = null; document.getElementById("print-summary").click()');
  await until('Boolean(window.printProof)');
  assert.equal(await evaluate('window.printProof.summary'), true);
  await evaluate('document.getElementById("clear-filters").click(); document.body.classList.add("print-summary"); document.querySelectorAll("details").forEach(d => d.open = true)');
  const pdf = await command("Page.printToPDF", { printBackground: true, preferCSSPageSize: true });
  fs.writeFileSync(path.join(output, "report-summary.pdf"), Buffer.from(pdf.data, "base64"));
  await evaluate('document.body.classList.remove("print-summary"); window.scrollTo(0, 0)');
  await command("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
  assert.equal(await evaluate('document.documentElement.scrollWidth <= innerWidth'), true, "mobile overflow");
  const mobile = await command("Page.captureScreenshot", { format: "png" });
  fs.writeFileSync(path.join(output, "report-mobile.png"), Buffer.from(mobile.data, "base64"));
  assert.deepEqual(errors, [], "browser errors");
  assert.deepEqual(requests.filter(url => /^https?:/.test(url)), [], "offline report made external requests");
  console.log("Browser checks passed: search, filters, sorting, links, print, mobile, offline.");
  await send("Browser.close");
}

main().catch(error => { console.error(error); process.exitCode = 1; }).finally(() => {
  clearTimeout(watchdog);
  if (socket) socket.close();
  if (child && child.exitCode === null) child.kill();
});
