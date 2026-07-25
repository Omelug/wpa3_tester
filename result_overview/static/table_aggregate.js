function autoAggregateTable(table) {
    const tbody = table.tBodies[0];
    const rows = tbody.rows;
    if (rows.length <= 1) return;

    const colCount = rows[0].cells.length;

    for (let colIdx = 0; colIdx < colCount; colIdx++) {
        let mainCell = null;
        let rowspan = 1;

        for (let i = 0; i < rows.length; i++) {
            const currentCell = rows[i].cells[colIdx];
            if (!currentCell) continue;

            if (!mainCell || currentCell.innerText.trim() !== mainCell.innerText.trim()) {
                if (rowspan > 1) mainCell.rowSpan = rowspan;
                mainCell = currentCell;
                rowspan = 1;
            } else {
                currentCell.style.display = 'none';
                rowspan++;
            }
        }

        if (rowspan > 1 && mainCell) mainCell.rowSpan = rowspan;
    }
}

function initTooltips() {
    document.querySelectorAll('.has-tooltip').forEach(el => {
        const tip = el.querySelector('.tooltip-content');
        if (!tip) return;
        el.addEventListener('mouseenter', () => {
            const rect = el.getBoundingClientRect();
            tip.style.top = (rect.bottom + 4) + 'px';
            tip.style.left = rect.left + 'px';
            tip.style.display = 'block';
        });
        el.addEventListener('mouseleave', () => { tip.style.display = 'none'; });
    });
}

document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("table.aggregate").forEach(autoAggregateTable);
    initTooltips();
});
