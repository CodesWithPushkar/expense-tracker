document.addEventListener('DOMContentLoaded', () => {

    // --- CONFIG ---
    const icons = ['ph-pizza', 'ph-car', 'ph-house', 'ph-lightning', 'ph-wifi-high', 'ph-t-shirt', 'ph-first-aid', 'ph-popcorn', 'ph-gift', 'ph-paw-print'];
    const colors = ['text-red-500', 'text-orange-500', 'text-green-500', 'text-blue-500', 'text-purple-500', 'text-pink-500'];
    
    // --- STATE ---
    const activeGroupId = localStorage.getItem('activeGroupId');

    // --- DOM ---
    const iconGrid = document.getElementById('icon-grid');
    const colorGrid = document.getElementById('color-grid');
    const categoryList = document.getElementById('category-list');
    const form = document.getElementById('category-form');
    const selectedIconInput = document.getElementById('selected-icon');
    const selectedColorInput = document.getElementById('selected-color');

    // --- INIT ---
    if (!activeGroupId) {
        alert("No active group found. Please select a group on the dashboard.");
        window.location.href = '/dashboard.html';
    } else {
        renderPickers();
        loadCategories();
    }

    // --- FUNCTIONS ---

    function renderPickers() {
        // Icons
        iconGrid.innerHTML = icons.map(icon => `
            <div class="icon-option cursor-pointer p-2 rounded hover:bg-gray-100 flex justify-center items-center text-2xl" data-val="${icon}">
                <i class="ph ${icon}"></i>
            </div>
        `).join('');

        // Colors
        colorGrid.innerHTML = colors.map(color => {
            const bgClass = color.replace('text-', 'bg-');
            return `<div class="color-option cursor-pointer w-8 h-8 rounded-full ${bgClass}" data-val="${color}"></div>`;
        }).join('');

        // Click Listeners
        iconGrid.querySelectorAll('.icon-option').forEach(el => {
            el.addEventListener('click', () => {
                document.querySelectorAll('.icon-option').forEach(i => i.classList.remove('selected'));
                el.classList.add('selected');
                selectedIconInput.value = el.dataset.val;
            });
        });

        colorGrid.querySelectorAll('.color-option').forEach(el => {
            el.addEventListener('click', () => {
                document.querySelectorAll('.color-option').forEach(c => c.classList.remove('ring-2', 'ring-offset-2', 'ring-blue-500', 'scale-110'));
                el.classList.add('ring-2', 'ring-offset-2', 'ring-blue-500', 'scale-110');
                selectedColorInput.value = el.dataset.val;
            });
        });
        
        // Select defaults
        if (iconGrid.children[0]) iconGrid.children[0].click();
        if (colorGrid.children[0]) colorGrid.children[0].click();
    }

    async function loadCategories() {
        try {
            // SEND GROUP ID IN QUERY PARAM
            const res = await fetch(`/api/categories?groupId=${activeGroupId}`);
            const categories = await res.json();
            
            if (categories.length === 0) {
                categoryList.innerHTML = '<p class="text-gray-400 text-center">No categories found.</p>';
                return;
            }

            categoryList.innerHTML = categories.map(cat => `
                <li class="flex justify-between items-center bg-gray-50 p-3 rounded-lg border">
                    <div class="flex items-center gap-3">
                        <i class="ph ${cat.icon} ${cat.color} text-2xl"></i>
                        <span class="font-semibold text-gray-700">${cat.name}</span>
                    </div>
                    <button onclick="deleteCategory('${cat._id}')" class="text-gray-400 hover:text-red-500 transition">
                        <i class="ph ph-trash text-xl"></i>
                    </button>
                </li>
            `).join('');
        } catch (err) {
            console.error("Failed to load categories", err);
        }
    }

    // --- ACTIONS ---

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const payload = {
            groupId: activeGroupId, // IMPORTANT: Send Group ID
            name: document.getElementById('cat-name').value,
            icon: selectedIconInput.value,
            color: selectedColorInput.value
        };

        const res = await fetch('/api/categories', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            form.reset();
            renderPickers(); // Reset selection
            loadCategories();
        } else {
            alert('Error creating category');
        }
    });

    window.deleteCategory = async (id) => {
        if (!confirm('Delete this category?')) return;
        await fetch(`/api/categories/${id}`, { method: 'DELETE' });
        loadCategories();
    };
});