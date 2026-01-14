document.addEventListener('DOMContentLoaded', async () => {
    
    // --- STATE ---
    let expenses = [];
    let members = [];
    let currentUser = null;
    const activeGroupId = localStorage.getItem('activeGroupId');

    // --- DOM ---
    const iouListEl = document.getElementById('iou-list');
    const balanceListEl = document.getElementById('balance-list');
    const groupNameDisplay = document.getElementById('group-name-display');
    const chartFilter = document.getElementById('chart-filter');
    
    // Charts instances (to destroy before redrawing)
    let catChartInstance = null;
    let trendChartInstance = null;

    if (!activeGroupId) { alert("No active group"); return window.location.href = '/dashboard.html'; }

    try {
        const [userRes, membersRes, expensesRes] = await Promise.all([
            fetch('/api/user'),
            fetch(`/api/group/members?groupId=${activeGroupId}`),
            fetch(`/api/expenses?groupId=${activeGroupId}`)
        ]);

        const userData = await userRes.json();
        currentUser = userData.user;
        members = await membersRes.json();
        expenses = await expensesRes.json();
        
        groupNameDisplay.textContent = userData.groups.find(g => g._id === activeGroupId)?.name || 'Group';

        calculateDebts();
        renderCharts('group'); // Default to Group view

        // Listener for Dropdown
        chartFilter.addEventListener('change', (e) => {
            renderCharts(e.target.value);
        });

    } catch (err) { console.error(err); }

    function calculateDebts() {
        let balances = {};
        members.forEach(m => balances[m._id] = { name: m.username, balance: 0 });

        expenses.forEach(exp => {
            const payerId = exp.paidBy._id;
            const amount = exp.amount;
            
            let splitUsers = exp.splitBetween && exp.splitBetween.length > 0 ? exp.splitBetween : members;
            splitUsers = splitUsers.filter(u => balances[u._id]);

            if (splitUsers.length === 0) return;

            const splitAmount = amount / splitUsers.length;

            if (balances[payerId]) balances[payerId].balance += amount;
            splitUsers.forEach(u => {
                if (balances[u._id]) balances[u._id].balance -= splitAmount;
            });
        });

        renderBalances(balances);
        renderSettlements(balances);
    }

    function renderBalances(balances) {
        balanceListEl.innerHTML = Object.values(balances).map(b => {
            const color = b.balance >= 0.01 ? 'text-green-600' : (b.balance <= -0.01 ? 'text-red-600' : 'text-gray-500');
            const sign = b.balance > 0 ? '+' : '';
            return `<li class="flex justify-between border-b pb-1"><span>${b.name}</span><span class="font-mono ${color}">${sign}₹${b.balance.toFixed(2)}</span></li>`;
        }).join('');
    }

    function renderSettlements(balances) {
        let debtors = Object.values(balances).filter(b => b.balance < -0.01).map(b => ({ ...b, amount: Math.abs(b.balance) }));
        let creditors = Object.values(balances).filter(b => b.balance > 0.01).map(b => ({ ...b, amount: b.balance }));
        debtors.sort((a, b) => b.amount - a.amount);
        creditors.sort((a, b) => b.amount - a.amount);

        let settlements = [];
        let i = 0, j = 0;

        while (i < debtors.length && j < creditors.length) {
            let debtor = debtors[i];
            let creditor = creditors[j];
            let amount = Math.min(debtor.amount, creditor.amount);

            settlements.push(`${debtor.name} pays ${creditor.name} <span class="font-bold">₹${amount.toFixed(2)}</span>`);
            debtor.amount -= amount;
            creditor.amount -= amount;
            if (debtor.amount < 0.01) i++;
            if (creditor.amount < 0.01) j++;
        }

        iouListEl.innerHTML = settlements.length ? settlements.map(s => `<li class="flex items-center gap-2"><i class="ph ph-arrow-right text-gray-400"></i> ${s}</li>`).join('') : '<p class="text-green-600">All settled!</p>';
    }

    function renderCharts(viewMode) {
        const categoryTotals = {};
        const monthlyTotals = {};

        expenses.forEach(exp => {
            let amountToAdd = 0;

            if (viewMode === 'group') {
                // Group View: Full Amount
                amountToAdd = exp.amount;
            } else {
                // Personal View: Only add MY share
                const splitIds = exp.splitBetween ? exp.splitBetween.map(u => u._id) : members.map(m => m._id);
                if (splitIds.includes(currentUser.id)) {
                    amountToAdd = exp.amount / splitIds.length;
                }
            }

            if (amountToAdd > 0) {
                // Category Data
                const cat = exp.categoryName || 'General';
                categoryTotals[cat] = (categoryTotals[cat] || 0) + amountToAdd;

                // Trend Data
                const month = new Date(exp.date).toLocaleString('default', { month: 'short' });
                monthlyTotals[month] = (monthlyTotals[month] || 0) + amountToAdd;
            }
        });

        // Destroy old charts if they exist
        if (catChartInstance) catChartInstance.destroy();
        if (trendChartInstance) trendChartInstance.destroy();

        // 1. Render Pie Chart
        catChartInstance = new Chart(document.getElementById('categoryChart'), {
            type: 'doughnut',
            data: {
                labels: Object.keys(categoryTotals),
                datasets: [{
                    data: Object.values(categoryTotals),
                    backgroundColor: ['#3b82f6', '#ef4444', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899', '#6366f1'],
                }]
            },
            options: {
                plugins: {
                    title: { display: true, text: viewMode === 'group' ? 'Overall Group Spending' : 'My Personal Share' }
                }
            }
        });

        // 2. Render Bar Chart
        trendChartInstance = new Chart(document.getElementById('trendChart'), {
            type: 'bar',
            data: {
                labels: Object.keys(monthlyTotals),
                datasets: [{
                    label: viewMode === 'group' ? 'Total Group Spending' : 'My Personal Spending',
                    data: Object.values(monthlyTotals),
                    backgroundColor: '#3b82f6',
                    borderRadius: 4
                }]
            }
        });
    }
});