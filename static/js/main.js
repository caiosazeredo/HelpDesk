// HelpDesk TI - JavaScript Principal

// Inicialização
document.addEventListener('DOMContentLoaded', function() {
    // Tooltips Bootstrap
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });
    
    // Auto-hide alerts após 5 segundos
    setTimeout(function() {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(alert => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
    
    // Animação de números (contadores)
    animateCounters();
    
    // Atualização em tempo real
    if (window.location.pathname === '/dashboard') {
        setInterval(updateDashboard, 30000); // Atualiza a cada 30 segundos
    }
});

// Função para animar contadores
function animateCounters() {
    const counters = document.querySelectorAll('.counter');
    
    counters.forEach(counter => {
        const target = +counter.getAttribute('data-target');
        const increment = target / 100;
        
        const updateCounter = () => {
            const current = +counter.innerText;
            
            if (current < target) {
                counter.innerText = Math.ceil(current + increment);
                setTimeout(updateCounter, 10);
            } else {
                counter.innerText = target;
            }
        };
        
        updateCounter();
    });
}

// Atualizar Dashboard via AJAX
function updateDashboard() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            // Atualizar contadores
            document.querySelector('#total-tickets').innerText = data.tickets.total;
            document.querySelector('#open-tickets').innerText = data.tickets.open;
            document.querySelector('#in-progress-tickets').innerText = data.tickets.in_progress;
            document.querySelector('#resolved-tickets').innerText = data.tickets.resolved;
            
            // Atualizar gamificação
            document.querySelector('#user-points').innerText = data.user.points + ' pts';
            document.querySelector('#user-level').innerText = 'Nível ' + data.user.level;
            document.querySelector('#user-streak').innerText = data.user.streak + ' dias';
            
            // Notificação de atualização
            showNotification('Dashboard atualizado!', 'success');
        })
        .catch(error => console.error('Erro ao atualizar dashboard:', error));
}

// Função para mostrar notificações
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show position-fixed top-0 end-0 m-3`;
    notification.style.zIndex = '9999';
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

// Atribuir ticket
function assignTicket(ticketId, technicianId = 'self') {
    fetch(`/tickets/${ticketId}/assign`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.content
        },
        body: JSON.stringify({ technician_id: technicianId })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Ticket atribuído com sucesso!', 'success');
            setTimeout(() => location.reload(), 1000);
        } else {
            showNotification('Erro ao atribuir ticket', 'danger');
        }
    })
    .catch(error => {
        console.error('Erro:', error);
        showNotification('Erro ao atribuir ticket', 'danger');
    });
}

// Atualizar status do ticket
function updateTicketStatus(ticketId, status) {
    fetch(`/tickets/${ticketId}/update_status`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.content
        },
        body: JSON.stringify({ status: status })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Status atualizado com sucesso!', 'success');
            setTimeout(() => location.reload(), 1000);
        } else {
            showNotification('Erro ao atualizar status', 'danger');
        }
    })
    .catch(error => {
        console.error('Erro:', error);
        showNotification('Erro ao atualizar status', 'danger');
    });
}

// Avaliar ticket
function rateTicket(ticketId, rating) {
    fetch(`/tickets/${ticketId}/rate`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.content
        },
        body: JSON.stringify({ rating: rating })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Avaliação enviada com sucesso!', 'success');
            // Atualizar estrelas visualmente
            updateStarDisplay(rating);
        } else {
            showNotification('Erro ao enviar avaliação', 'danger');
        }
    })
    .catch(error => {
        console.error('Erro:', error);
        showNotification('Erro ao enviar avaliação', 'danger');
    });
}

// Atualizar display de estrelas
function updateStarDisplay(rating) {
    const stars = document.querySelectorAll('.rating-star');
    stars.forEach((star, index) => {
        if (index < rating) {
            star.classList.remove('far');
            star.classList.add('fas', 'text-warning');
        } else {
            star.classList.remove('fas', 'text-warning');
            star.classList.add('far');
        }
    });
}

// Sistema de busca em tempo real
function searchTickets(query) {
    const tickets = document.querySelectorAll('.ticket-item');
    
    tickets.forEach(ticket => {
        const text = ticket.textContent.toLowerCase();
        if (text.includes(query.toLowerCase())) {
            ticket.style.display = '';
        } else {
            ticket.style.display = 'none';
        }
    });
}

// Animação de conquista desbloqueada
function unlockAchievement(badgeName, badgeIcon) {
    const achievement = document.createElement('div');
    achievement.className = 'achievement-unlock';
    achievement.innerHTML = `
        <div class="achievement-content">
            <i class="fas ${badgeIcon} fa-3x text-warning mb-2"></i>
            <h5>Conquista Desbloqueada!</h5>
            <p>${badgeName}</p>
        </div>
    `;
    
    document.body.appendChild(achievement);
    
    setTimeout(() => {
        achievement.classList.add('show');
    }, 100);
    
    setTimeout(() => {
        achievement.remove();
    }, 5000);
}

// Gráfico de exemplo para relatórios
function createChart(canvasId, type, data, options = {}) {
    const ctx = document.getElementById(canvasId);
    if (ctx) {
        new Chart(ctx, {
            type: type,
            data: data,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                ...options
            }
        });
    }
}

// Dark mode toggle
function toggleDarkMode() {
    document.body.classList.toggle('dark-mode');
    const isDarkMode = document.body.classList.contains('dark-mode');
    localStorage.setItem('darkMode', isDarkMode);
}

// Verificar preferência de dark mode
if (localStorage.getItem('darkMode') === 'true') {
    document.body.classList.add('dark-mode');
}