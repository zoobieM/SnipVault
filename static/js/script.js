// SnipVault JavaScript

// Copy to clipboard functionality
document.addEventListener('click', (e) => {
    const btn = e.target.closest('.copy-btn');
    if (!btn) return;
    
    const text = btn.getAttribute('data-content');
    if (!text) return;
    
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
            const original = btn.textContent;
            btn.textContent = '✓ Copied!';
            setTimeout(() => btn.textContent = original, 2000);
        }).catch(() => {
            fallbackCopy(text, btn);
        });
    } else {
        fallbackCopy(text, btn);
    }
});

function fallbackCopy(text, btn) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    
    try {
        const ok = document.execCommand('copy');
        if (ok) {
            const original = btn.textContent;
            btn.textContent = '✓ Copied!';
            setTimeout(() => btn.textContent = original, 2000);
        }
    } catch (e) {
        alert('Copy failed. Please select and copy manually.');
    } finally {
        document.body.removeChild(ta);
    }
}

// Edit functionality
document.addEventListener('click', (e) => {
    // Edit button
    const editBtn = e.target.closest('.edit-btn');
    if (editBtn) {
        const id = editBtn.getAttribute('data-id');
        const content = document.getElementById(`content-${id}`);
        const form = document.getElementById(`edit-form-${id}`);
        
        if (content && form) {
            content.style.display = 'none';
            form.style.display = 'block';
            form.querySelector('textarea').focus();
        }
        return;
    }
    
    // Cancel button
    const cancelBtn = e.target.closest('.cancel-edit');
    if (cancelBtn) {
        const id = cancelBtn.getAttribute('data-id');
        const content = document.getElementById(`content-${id}`);
        const form = document.getElementById(`edit-form-${id}`);
        
        if (content && form) {
            content.style.display = 'block';
            form.style.display = 'none';
        }
        return;
    }
});

// Delete confirmation modal
let deleteForm = null;

document.addEventListener('click', (e) => {
    const deleteBtn = e.target.closest('.btn-danger');
    if (deleteBtn && deleteBtn.type === 'submit') {
        e.preventDefault();
        deleteForm = deleteBtn.closest('form');
        showDeleteModal();
    }
});

function showDeleteModal() {
    const modal = document.createElement('div');
    modal.className = 'delete-modal';
    modal.innerHTML = `
        <div class="modal-overlay"></div>
        <div class="modal-content">
            <h3>Delete Snippet?</h3>
            <p>Are you sure you want to delete this snippet? This action cannot be undone.</p>
            <div class="modal-actions">
                <button class="btn btn-secondary btn-sm" onclick="closeDeleteModal()">Cancel</button>
                <button class="btn btn-danger btn-sm" onclick="confirmDelete()">Delete</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    
    // Close on overlay click
    modal.querySelector('.modal-overlay').addEventListener('click', closeDeleteModal);
}

function closeDeleteModal() {
    const modal = document.querySelector('.delete-modal');
    if (modal) {
        modal.remove();
    }
    deleteForm = null;
}

function confirmDelete() {
    if (deleteForm) {
        deleteForm.submit();
    }
    closeDeleteModal();
}

// Auto-hide flash messages after 5 seconds
setTimeout(() => {
    const flashes = document.querySelectorAll('.flash');
    flashes.forEach(flash => {
        flash.style.transition = 'opacity 0.5s';
        flash.style.opacity = '0';
        setTimeout(() => flash.remove(), 500);
    });
}, 5000);
