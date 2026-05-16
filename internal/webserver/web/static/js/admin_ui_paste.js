// This file contains JS code for the paste view.
// All files named admin_*.js will be merged together and minimised by calling
// go generate ./...

function pasteToggleDownloads(checkbox) {
    document.getElementById("paste-downloads").disabled = !checkbox.checked;
}

function pasteToggleExpiry(checkbox) {
    document.getElementById("paste-expiry").disabled = !checkbox.checked;
}

function pasteTogglePassword(checkbox) {
    document.getElementById("paste-password").disabled = !checkbox.checked;
}

function submitPaste() {
    const content = document.getElementById("paste-content").value.trim();
    if (!content) {
        alert("Please enter some content before creating a paste.");
        return;
    }

    const title = document.getElementById("paste-title").value.trim();
    const limitViews = document.getElementById("paste-enable-downloads").checked;
    const limitExpiry = document.getElementById("paste-enable-expiry").checked;
    const usePassword = document.getElementById("paste-enable-password").checked;

    const allowedDownloads = limitViews ? parseInt(document.getElementById("paste-downloads").value, 10) : 0;
    const expiryDays = limitExpiry ? parseInt(document.getElementById("paste-expiry").value, 10) : 0;
    const password = usePassword ? document.getElementById("paste-password").value : "";

    apiAddPaste(content, title, allowedDownloads, expiryDays, password)
        .then(data => {
            pasteInsertRow(data);
            document.getElementById("paste-content").value = "";
            document.getElementById("paste-title").value = "";
            pasteCopyUrl(data.UrlDownload, data.Id);
        })
        .catch(error => {
            alert("Failed to create paste: " + error);
            console.error("Error:", error);
        });
}

function pasteInsertRow(info) {
    const tbody = document.getElementById("paste-tbody");
    const row = document.createElement("tr");
    row.id = "pasterow-" + info.Id;
    const viewsRemaining = info.UnlimitedDownloads ? "Unlimited" : info.DownloadsRemaining;

    const cells = [
        { text: info.Name },
        { id: `paste-created-${info.Id}` },
        { text: String(info.DownloadCount) },
        { id: `paste-expiry-${info.Id}` },
        { text: String(viewsRemaining) },
    ];

    if (canViewOtherUploads) {
        cells.push({ text: userNameSelf });
    }

    for (const cell of cells) {
        const td = document.createElement("td");
        td.className = "newItem";
        if (cell.id) {
            const span = document.createElement("span");
            span.id = cell.id;
            td.appendChild(span);
        } else {
            td.textContent = cell.text;
        }
        row.appendChild(td);
    }

    const actionsTd = document.createElement("td");
    actionsTd.className = "newItem";

    const btnGroup = document.createElement("div");
    btnGroup.className = "btn-group";
    btnGroup.role = "group";

    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.className = "btn btn-outline-light btn-sm";
    copyBtn.title = "Copy URL";
    copyBtn.addEventListener("click", () => pasteCopyUrl(info.UrlDownload, info.Id));
    const copyIcon = document.createElement("i");
    copyIcon.className = "bi bi-copy";
    copyBtn.appendChild(copyIcon);

    const deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.className = "btn btn-outline-danger btn-sm";
    deleteBtn.title = "Delete";
    deleteBtn.addEventListener("click", () => pasteDelete(info.Id));
    const deleteIcon = document.createElement("i");
    deleteIcon.className = "bi bi-trash3";
    deleteBtn.appendChild(deleteIcon);

    btnGroup.appendChild(copyBtn);
    btnGroup.appendChild(deleteBtn);
    actionsTd.appendChild(btnGroup);
    row.appendChild(actionsTd);

    tbody.prepend(row);

    insertDateWithNegative(info.UploadDate, `paste-created-${info.Id}`, "Unknown");
    if (info.UnlimitedTime) {
        document.getElementById(`paste-expiry-${info.Id}`).innerText = "Never";
    } else {
        insertFileRequestExpiry(info.ExpireAt, `paste-expiry-${info.Id}`);
    }
}

function pasteCopyUrl(url, id) {
    navigator.clipboard.writeText(url).then(() => {
        const toastEl = document.getElementById("paste-toast");
        document.getElementById("paste-toast-body").innerText = "URL copied to clipboard!";
        bootstrap.Toast.getOrCreateInstance(toastEl).show();
    }).catch(() => {
        prompt("Copy this URL:", url);
    });
}

function pasteDelete(id) {
    if (!confirm("Delete this paste?")) {
        return;
    }
    apiFilesDelete(id, 0)
        .then(() => {
            const row = document.getElementById("pasterow-" + id);
            if (row) {
                row.classList.add("rowDeleting");
                setTimeout(() => row.remove(), 290);
            }
        })
        .catch(error => {
            alert("Failed to delete paste: " + error);
            console.error("Error:", error);
        });
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}
