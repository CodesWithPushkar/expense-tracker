document.addEventListener('DOMContentLoaded', async () => {
    
    // --- STATE ---
    const activeGroupId = localStorage.getItem('activeGroupId');
    const groupNameDisplay = document.getElementById('group-name-display');
    const historyList = document.getElementById('history-list');

    if (!activeGroupId) {
        alert("No active group selected.");
        window.location.href = '/dashboard.html';
        return;
    }

    try {
        // Fetch User Info (for group name) & History Logs
        const [userRes, historyRes] = await Promise.all([
            fetch('/api/user'),
            fetch(`/api/history?groupId=${activeGroupId}`)
        ]);

        const userData = await userRes.json();
        const logs = await historyRes.json();

        // Set Group Name
        const currentGroup = userData.groups.find(g => g._id === activeGroupId);
        groupNameDisplay.textContent = currentGroup ? currentGroup.name : 'Unknown Group';

        renderHistory(logs);

    } catch (err) {
        console.error("Error loading history:", err);
        historyList.innerHTML = '<p class="text-red-500 pl-6">Failed to load history.</p>';
    }

    function renderHistory(logs) {
        if (logs.length === 0) {
            historyList.innerHTML = '<p class="text-gray-500 pl-6">No activity recorded yet.</p>';
            return;
        }

        historyList.innerHTML = logs.map(log => {
            const date = new Date(log.date).toLocaleString();
            
            // Color coding based on action
            let iconColor = 'bg-gray-500';
            let icon = 'ph-info';
            
            if (log.action === 'CREATED') {
                iconColor = 'bg-green-500';
                icon = 'ph-plus';
            } else if (log.action === 'DELETED') {
                iconColor = 'bg-red-500';
                icon = 'ph-trash';
            } else if (log.action === 'EDITED') {
                iconColor = 'bg-orange-500';
                icon = 'ph-pencil-simple';
            }

            return `
            <div class="mb-6 ml-6 relative">
                <span class="absolute -left-10 flex items-center justify-center w-8 h-8 ${iconColor} rounded-full ring-4 ring-white text-white">
                    <i class="ph ${icon}"></i>
                </span>
                
                <div class="bg-gray-50 p-4 rounded-lg border hover:shadow-sm transition">
                    <div class="flex justify-between items-start">
                        <div>
                            <p class="text-sm font-bold text-gray-900">
                                ${log.user ? log.user.username : 'Unknown User'} 
                                <span class="font-normal text-gray-600">${log.action.toLowerCase()} an expense</span>
                            </p>
                            <p class="text-gray-800 mt-1">${log.description}</p>
                        </div>
                        <span class="text-xs text-gray-400 whitespace-nowrap ml-2">${date}</span>
                    </div>
                </div>
            </div>
            `;
        }).join('');
    }
});