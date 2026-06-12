function autoAggregateTable(tableId) {
    const table = document.getElementById(tableId);
    if (!table) return;

    const tbody = table.tBodies[0];
    const rows = tbody.rows;
    if (rows.length <= 1) return;

    const colCount = rows[0].cells.length;
    const columnsToAggregate = Array.from({ length: colCount }, (_, i) => i);

    columnsToAggregate.forEach(colIdx => {
        let mainCell = null;
        let rowspan = 1;

        for (let i = 0; i < rows.length; i++) {
            const currentCell = rows[i].cells[colIdx];
            if (!currentCell) continue;

            if (!mainCell || currentCell.innerText.trim() !== mainCell.innerText.trim() || currentCell.innerText.trim() === "?") {
                if (rowspan > 1) mainCell.rowSpan = rowspan;
                mainCell = currentCell;
                rowspan = 1;
            } else {
                currentCell.style.display = 'none';
                rowspan++;
            }
        }

        if (rowspan > 1 && mainCell) mainCell.rowSpan = rowspan;
    });
}

document.addEventListener("DOMContentLoaded", () => {
    autoAggregateTable("resultsTable");
});