// Local-only report controls. No data leaves this document.
(function () {
  "use strict";
  const tools = document.querySelector(".report-tools");
  if (!tools) return;
  tools.hidden = false;
  const search = document.getElementById("report-search");
  const severity = document.getElementById("filter-severity");
  const evidence = document.getElementById("filter-evidence");
  const project = document.getElementById("filter-project");
  const status = document.getElementById("filter-status");
  const cards = Array.from(document.querySelectorAll(".finding"));
  const texts = new Map(cards.map(card => [card, card.textContent.toLocaleLowerCase()]));
  const inventoryRows = Array.from(document.querySelectorAll("details.inv table tr"))
    .filter(row => row.querySelector("td"));
  const rowTexts = new Map(inventoryRows.map(row => [row, row.textContent.toLocaleLowerCase()]));
  let searchState = null;
  let printing = false;
  let printState = null;

  function openParents(node) {
    let details = node.closest("details");
    while (details) {
      details.open = true;
      details = details.parentElement.closest("details");
    }
  }

  function detailsState() {
    return Array.from(document.querySelectorAll("details"), node => [node, node.open]);
  }

  function restoreDetails(state) {
    if (state) state.forEach(([node, open]) => { node.open = open; });
  }

  function applyFilters() {
    if (printing) return;
    const query = search.value.trim().toLocaleLowerCase();
    if (query && !searchState) searchState = detailsState();
    if (!query && searchState) {
      restoreDetails(searchState);
      searchState = null;
    }
    let shown = 0;
    cards.forEach(card => {
      const projects = JSON.parse(card.dataset.projects || "[]");
      const matchesProject = !project.value || (project.value === "__unassigned__"
        ? projects.length === 0 : projects.includes(project.value));
      card.hidden = !(matchesProject
        && (!severity.value || card.dataset.severity === severity.value)
        && (!evidence.value || card.dataset.evidence === evidence.value)
        && (!query || texts.get(card).includes(query)));
      if (!card.hidden) {
        shown += 1;
        if (query) {
          openParents(card);
          card.querySelectorAll("details").forEach(node => { node.open = true; });
        }
      }
    });
    document.querySelectorAll("[data-finding]").forEach(row => {
      const card = document.getElementById(row.dataset.finding);
      row.hidden = card ? card.hidden : false;
    });
    let inventoryMatches = 0;
    inventoryRows.forEach(row => {
      row.hidden = Boolean(query) && !rowTexts.get(row).includes(query);
      if (!row.hidden && query) { inventoryMatches += 1; openParents(row); }
    });
    status.textContent = `${shown} of ${cards.length} findings shown.`
      + (query ? ` ${inventoryMatches} inventory rows match the search.` : "")
      + (shown === 0 ? " No findings match the current filters." : "");
  }
  [search, severity, evidence, project].forEach(control => {
    control.addEventListener("input", applyFilters);
  });
  document.getElementById("clear-filters").addEventListener("click", () => {
    [search, severity, evidence, project].forEach(control => { control.value = ""; });
    applyFilters();
  });

  // Follow evidence links even when a filter currently hides the target.
  document.addEventListener("click", event => {
    const link = event.target.closest('a[href^="#"]');
    if (!link) return;
    const card = document.getElementById(decodeURIComponent(link.hash.slice(1)));
    if (card && card.classList.contains("finding") && card.hidden) {
      [search, severity, evidence, project].forEach(control => { control.value = ""; });
      applyFilters();
      openParents(card);
      card.scrollIntoView();
    }
  });

  // Real header buttons support keyboard sorting. Numeric columns retain numeric order.
  document.querySelectorAll("table").forEach(table => {
    const header = table.rows[0];
    if (!header || !header.querySelector("th")) return;
    // A thead also repeats the header in printed multipage tables.
    const head = table.tHead || table.createTHead();
    head.appendChild(header);
    Array.from(header.cells).forEach((cell, column) => {
      const label = cell.textContent.trim();
      const button = document.createElement("button");
      button.type = "button";
      button.className = "sort-button";
      button.textContent = label;
      button.setAttribute("aria-label", `Sort by ${label}`);
      cell.replaceChildren(button);
      cell.setAttribute("scope", "col");
      button.addEventListener("click", () => {
        const ascending = cell.getAttribute("aria-sort") !== "ascending";
        Array.from(header.cells).forEach(other => other.removeAttribute("aria-sort"));
        cell.setAttribute("aria-sort", ascending ? "ascending" : "descending");
        Array.from(table.tBodies).forEach(body => {
          const rows = Array.from(body.rows);
          // Keep total/footer rows at the bottom, not interspersed with data.
          const dataRows = rows.filter(row => !row.querySelector("td > strong"));
          const totals = rows.filter(row => row.querySelector("td > strong"));
          dataRows.sort((left, right) => {
            const a = (left.cells[column]?.textContent || "").trim();
            const b = (right.cells[column]?.textContent || "").trim();
            const na = Number(a.replace(/[, %]/g, ""));
            const nb = Number(b.replace(/[, %]/g, ""));
            const numeric = a !== "" && b !== "" && Number.isFinite(na) && Number.isFinite(nb);
            const comparison = numeric ? na - nb : a.localeCompare(b, undefined, { numeric: true });
            return ascending ? comparison : -comparison;
          });
          [...dataRows, ...totals].forEach(row => body.appendChild(row));
        });
      });
    });
  });

  if (document.getElementById("summary")) {
    document.querySelectorAll("details.sec:not(#summary)").forEach(section => {
      const link = document.createElement("a");
      link.href = "#summary";
      link.className = "back-summary";
      link.textContent = "Return to summary";
      section.querySelector(".secbody").appendChild(link);
    });
  }

  function preparePrint() {
    if (printState) return;
    printing = true;
    printState = {
      details: detailsState(),
      hidden: [...cards, ...inventoryRows, ...document.querySelectorAll("[data-finding]")]
        .filter(node => node.hidden),
    };
    printState.hidden.forEach(node => { node.hidden = false; });
    document.querySelectorAll("details").forEach(node => { node.open = true; });
  }

  function restorePrint() {
    if (!printState) return;
    restoreDetails(printState.details);
    printState.hidden.forEach(node => { node.hidden = true; });
    document.body.classList.remove("print-summary");
    printState = null;
    printing = false;
    document.querySelectorAll("#print-summary, #print-full").forEach(button => {
      button.disabled = button.id === "print-summary" && !document.getElementById("summary");
    });
  }

  async function printReport(summary) {
    if (printing) return;
    document.body.classList.toggle("print-summary", summary);
    preparePrint();
    document.querySelectorAll("#print-summary, #print-full").forEach(button => { button.disabled = true; });
    status.textContent = "Preparing report for printing…";
    try {
      // Explicit print controls wait for diagrams; Ctrl+P cannot await rendering.
      if (!summary && typeof renderRevealed === "function") await renderRevealed(document);
      await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      window.print();
    } catch (error) {
      restorePrint();
      status.textContent = "Print preparation failed. Reload the report and try again.";
      return;
    }
    // afterprint restores the live view, including cancellation.
  }
  document.getElementById("print-summary").addEventListener("click", () => printReport(true));
  document.getElementById("print-full").addEventListener("click", () => printReport(false));
  window.addEventListener("beforeprint", preparePrint);
  window.addEventListener("afterprint", () => { restorePrint(); applyFilters(); });
  applyFilters();
})();
