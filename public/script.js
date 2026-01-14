document.addEventListener('DOMContentLoaded', async () => {
    
    // --- STATE ---
    let currentUser = null;
    let myGroups = [];
    let groupMembers = [];
    let activeGroupId = localStorage.getItem('activeGroupId');

    // --- DOM ---
    const groupModal = document.getElementById('group-modal');
    const groupBanner = document.getElementById('group-banner');
    const groupNameDisplay = document.getElementById('group-name-display');
    const groupCodeDisplay = document.getElementById('group-code-display');
    const catSelect = document.getElementById('category-select');
    const splitCheckboxes = document.getElementById('split-checkboxes');
    const transactionList = document.getElementById('transaction-list');
    const groupListDropdown = document.getElementById('group-list-dropdown');
    const currentGroupNameBtn = document.getElementById('current-group-name');
    
    const expenseForm = document.getElementById('expense-form');
    const editIdInput = document.getElementById('edit-expense-id');
    const btnSubmit = document.getElementById('btn-submit-expense');
    const btnCancel = document.getElementById('btn-cancel-edit');

    // --- INIT ---
    try {
        const res = await fetch('/api/user');
        if (res.status === 401) return window.location.href = '/login.html';
        const data = await res.json();
        currentUser = data.user;
        myGroups = data.groups;

        if (myGroups.length === 0) groupModal.classList.remove('hidden');
        else {
            if (!activeGroupId || !myGroups.find(g => g._id === activeGroupId)) {
                activeGroupId = myGroups[0]._id;
                localStorage.setItem('activeGroupId', activeGroupId);
            }
            initDashboard();
        }
    } catch (err) { console.error(err); }

    // --- DASHBOARD ---
    async function initDashboard() {
        const activeGroup = myGroups.find(g => g._id === activeGroupId);
        groupBanner.classList.remove('hidden');
        groupNameDisplay.textContent = activeGroup.name;
        groupCodeDisplay.textContent = activeGroup.code;
        currentGroupNameBtn.textContent = activeGroup.name;

        groupListDropdown.innerHTML = myGroups.map(g => `
            <button onclick="switchGroup('${g._id}')" class="w-full text-left px-3 py-2 hover:bg-gray-100 rounded text-sm ${g._id === activeGroupId ? 'font-bold text-blue-600' : 'text-gray-700'}">${g.name}</button>
        `).join('');

        const [membersRes, catRes, expRes] = await Promise.all([
            fetch(`/api/group/members?groupId=${activeGroupId}`),
            fetch(`/api/categories?groupId=${activeGroupId}`),
            fetch(`/api/expenses?groupId=${activeGroupId}`)
        ]);

        groupMembers = await membersRes.json();
        const categories = await catRes.json();
        const expenses = await expRes.json();
        
        catSelect.innerHTML = categories.map(c => `<option value="${c.name}">${c.name}</option>`).join('');

        splitCheckboxes.innerHTML = groupMembers.map(m => `
            <label class="flex items-center space-x-2">
                <input type="checkbox" value="${m._id}" checked class="split-check form-checkbox text-blue-600">
                <span>${m.username}</span>
            </label>
        `).join('');

        renderExpenses(expenses);
    }

    function renderExpenses(expenses) {
        if (expenses.length === 0) {
            transactionList.innerHTML = '<p class="text-gray-500 text-center py-8">No expenses yet.</p>';
            return;
        }
        transactionList.innerHTML = expenses.map(exp => {
            const isMe = exp.paidBy._id === currentUser.id;
            
            // Meta info
            const creatorName = exp.createdBy ? exp.createdBy.username : 'Unknown';
            const creatorId = exp.createdBy ? exp.createdBy._id : '';
            
            let metaHtml = `<span class="text-gray-400">Added by ${creatorName}</span>`;
            if (exp.lastEditedBy) {
                metaHtml = `<span class="text-red-500 font-semibold">Edited by ${exp.lastEditedBy.username}</span>`;
            }

            // Get List of Split Names
            const splitNamesList = exp.splitBetween && exp.splitBetween.length > 0 
                ? exp.splitBetween.map(u => u.username) 
                : ['Everyone'];
            
            const splitNamesString = splitNamesList.join(', ');

            // Escape strings for HTML attributes
            const safeCreatorName = creatorName.replace(/'/g, "\\'"); 
            const safeSplitNames = splitNamesString.replace(/'/g, "\\'");

            return `
            <div class="bg-gray-50 p-4 rounded-lg border hover:shadow-sm transition group relative">
                <div class="flex justify-between items-start">
                    <div class="flex items-center gap-3">
                        <div class="bg-blue-100 p-2 rounded-full text-blue-600"><i class="ph ph-receipt text-xl"></i></div>
                        <div>
                            <p class="font-bold text-gray-800">${exp.description}</p>
                            <p class="text-xs text-gray-500 mb-1">${isMe ? 'You' : exp.paidBy.username} paid • For: ${splitNamesString}</p>
                            <p class="text-xs">${metaHtml}</p>
                        </div>
                    </div>
                    <div class="text-right">
                        <span class="font-bold text-lg text-gray-700 block">₹${exp.amount.toFixed(2)}</span>
                        <div class="mt-2 space-x-2 opacity-0 group-hover:opacity-100 transition">
                            <button onclick='editExpense(${JSON.stringify(exp)}, "${safeSplitNames}")' class="text-blue-500 hover:text-blue-700 text-sm font-semibold">Edit</button>
                            <button onclick="deleteExpense('${exp._id}', '${safeCreatorName}', '${creatorId}', '${safeSplitNames}')" class="text-red-500 hover:text-red-700 text-sm font-semibold">Delete</button>
                        </div>
                    </div>
                </div>
            </div>`;
        }).join('');
    }

    // --- ACTIONS ---
    window.switchGroup = (id) => { localStorage.setItem('activeGroupId', id); location.reload(); };

    // --- DELETE WITH CONTEXT ---
    window.deleteExpense = async (id, creatorName, creatorId, splitNames) => {
        let confirmMsg = 'Are you sure you want to delete this expense?';

        // Custom message if someone else created it
        if (creatorId && creatorId !== currentUser.id) {
            confirmMsg = `User '${creatorName}' added this expense for: [ ${splitNames} ]\n\nDo you still want to delete it?`;
        } else {
             // Even if I created it, remind me who it affects
            confirmMsg = `This expense is shared with: [ ${splitNames} ]\n\nDelete it?`;
        }

        if (!confirm(confirmMsg)) return;

        await fetch(`/api/expenses/${id}`, { method: 'DELETE' });
        initDashboard();
    };

    // --- EDIT WITH CONTEXT ---
    window.editExpense = (exp, splitNames) => {
        const creatorId = exp.createdBy ? exp.createdBy._id : null;
        const creatorName = exp.createdBy ? exp.createdBy.username : 'Unknown';

        // Check ownership
        if (creatorId && creatorId !== currentUser.id) {
            const confirmMsg = `User '${creatorName}' added this expense for: [ ${splitNames} ]\n\nDo you want to edit it?`;
            if (!confirm(confirmMsg)) return;
        }

        // Fill Form
        editIdInput.value = exp._id;
        document.getElementById('desc').value = exp.description;
        document.getElementById('amount').value = exp.amount;
        catSelect.value = exp.categoryName;

        const splitIds = exp.splitBetween.map(u => u._id);
        document.querySelectorAll('.split-check').forEach(cb => {
            cb.checked = splitIds.includes(cb.value);
        });

        btnSubmit.textContent = "Update Expense";
        btnSubmit.classList.add('bg-orange-500', 'hover:bg-orange-600');
        btnCancel.classList.remove('hidden');
    };

    btnCancel.onclick = () => {
        expenseForm.reset();
        editIdInput.value = '';
        btnSubmit.textContent = "Add Expense";
        btnSubmit.classList.remove('bg-orange-500', 'hover:bg-orange-600');
        btnCancel.classList.add('hidden');
        document.querySelectorAll('.split-check').forEach(cb => cb.checked = true);
    };

    expenseForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const checkedBoxes = document.querySelectorAll('.split-check:checked');
        const splitBetweenIds = Array.from(checkedBoxes).map(cb => cb.value);

        if (splitBetweenIds.length === 0) return alert("Please select at least one person to split with.");

        const payload = {
            groupId: activeGroupId,
            description: document.getElementById('desc').value,
            totalAmount: parseFloat(document.getElementById('amount').value),
            date: new Date(),
            categoryName: catSelect.value,
            payerType: 'me',
            splitBetween: splitBetweenIds
        };

        const id = editIdInput.value;
        const method = id ? 'PUT' : 'POST';
        const url = id ? `/api/expenses/${id}` : '/api/expenses';

        const res = await fetch(url, {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            btnCancel.click();
            initDashboard();
        }
    });

    // ... (Group Logic remains same) ...
    document.getElementById('btn-add-group').onclick = () => groupModal.classList.remove('hidden');
    document.getElementById('tab-join').onclick = (e) => { e.preventDefault(); document.getElementById('join-group-form').classList.remove('hidden'); document.getElementById('create-group-form').classList.add('hidden'); };
    document.getElementById('tab-create').onclick = (e) => { e.preventDefault(); document.getElementById('create-group-form').classList.remove('hidden'); document.getElementById('join-group-form').classList.add('hidden'); };

    async function handleGroupAction(action, payload) {
        const res = await fetch('/api/groups/join', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action, ...payload }) });
        const data = await res.json();
        if (data.error) alert(data.error); else { localStorage.setItem('activeGroupId', data._id); location.reload(); }
    }
    document.getElementById('join-group-form').onsubmit = (e) => { e.preventDefault(); handleGroupAction('join', { groupCode: document.getElementById('join-code').value.toUpperCase() }); };
    document.getElementById('create-group-form').onsubmit = (e) => { e.preventDefault(); handleGroupAction('create', { groupName: document.getElementById('create-name').value, groupCode: document.getElementById('create-code').value.toUpperCase() }); };
});