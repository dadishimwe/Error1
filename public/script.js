let csrfToken = null;

// Fetch CSRF token
function fetchCsrfToken() {
  return fetch('/csrf-token')
    .then(res => res.json())
    .then(data => csrfToken = data.token);
}

function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function showLogin() {
  document.getElementById('login-section').style.display = 'block';
  document.getElementById('signup-section').style.display = 'none';
  document.getElementById('dashboard').style.display = 'none';
}

function showSignup() {
  document.getElementById('login-section').style.display = 'none';
  document.getElementById('signup-section').style.display = 'block';
}

function showDashboard() {
  document.getElementById('login-section').style.display = 'none';
  document.getElementById('signup-section').style.display = 'none';
  document.getElementById('dashboard').style.display = 'block';
  showSection('expenses');
}

function showSection(section) {
  const sections = ['expenses', 'inventory', 'clients', 'issues'];
  sections.forEach(sec => {
    document.getElementById(`${sec}-section`).style.display = sec === section ? 'block' : 'none';
  });
  if (section === 'expenses') loadExpenses();
  else if (section === 'inventory') loadInventory();
  else if (section === 'clients') loadClients();
  else if (section === 'issues') loadIssues();
}

document.getElementById('login-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const btn = e.target.querySelector('button');
  btn.disabled = true;
  btn.textContent = 'Logging in...';
  const username = document.getElementById('login-username').value;
  const password = document.getElementById('login-password').value;
  fetch('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  })
    .then(res => res.json())
    .then(data => {
      btn.disabled = false;
      btn.textContent = 'Login';
      if (data.error) throw new Error(data.error);
      fetchCsrfToken().then(() => showDashboard());
    })
    .catch(err => {
      btn.disabled = false;
      btn.textContent = 'Login';
      alert(err.message);
    });
});

document.getElementById('signup-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const btn = e.target.querySelector('button');
  btn.disabled = true;
  btn.textContent = 'Signing up...';
  const username = document.getElementById('signup-username').value;
  const name = document.getElementById('signup-name').value;
  const password = document.getElementById('signup-password').value;
  fetch('/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, name, password })
  })
    .then(res => res.json())
    .then(data => {
      btn.disabled = false;
      btn.textContent = 'Sign Up';
      if (data.error) throw new Error(data.error);
      showLogin();
    })
    .catch(err => {
      btn.disabled = false;
      btn.textContent = 'Sign Up';
      alert(err.message);
    });
});

function logout() {
  fetch('/logout')
    .then(() => showLogin());
}

function loadExpenses() {
  fetch('/expenses')
    .then(res => res.json())
    .then(data => {
      const tbody = document.getElementById('expenses-table').querySelector('tbody');
      tbody.innerHTML = '';
      data.forEach(exp => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${escapeHtml(exp.staffName)}</td>
          <td>${escapeHtml(exp.date)}</td>
          <td>${escapeHtml(exp.amount.toString())}</td>
          <td>${escapeHtml(exp.description)}</td>
          <td>${escapeHtml(exp.status)}</td>
          <td>${escapeHtml(exp.adminNote || '')}</td>
          <td>${exp.status === 'Pending' ? `<button onclick="reimburse(${exp.id})">Reimburse</button>` : ''}</td>
        `;
        tbody.appendChild(tr);
      });
    })
    .catch(err => alert('Failed to load expenses: ' + err.message));
}

document.getElementById('expense-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const btn = document.getElementById('submit-expense-btn');
  btn.disabled = true;
  btn.textContent = 'Submitting...';
  const amount = document.getElementById('expense-amount').value;
  const description = document.getElementById('expense-description').value;
  const date = document.getElementById('expense-date').value;
  fetch('/expenses', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
    body: JSON.stringify({ amount, description, date })
  })
    .then(res => res.json())
    .then(() => {
      btn.disabled = false;
      btn.textContent = 'Submit';
      loadExpenses();
    })
    .catch(err => {
      btn.disabled = false;
      btn.textContent = 'Submit';
      alert('Failed to submit expense: ' + err.message);
    });
});

function reimburse(id) {
  const adminNote = prompt('Enter admin note:');
  fetch(`/expenses/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
    body: JSON.stringify({ status: 'Reimbursed', adminNote })
  })
    .then(() => loadExpenses())
    .catch(err => alert('Failed to reimburse expense: ' + err.message));
}

function loadInventory() {
  fetch('/inventory')
    .then(res => res.json())
    .then(data => {
      const tbody = document.getElementById('inventory-table').querySelector('tbody');
      tbody.innerHTML = '';
      data.forEach(item => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${escapeHtml(item.item_type)}</td>
          <td>${escapeHtml(item.item_id)}</td>
          <td>${escapeHtml(item.status)}</td>
          <td>${escapeHtml(item.location)}</td>
          <td>${escapeHtml(item.checkedOutTo || '')}</td>
          <td>
            <button onclick="updateInventory(${item.id}, 'Checked Out')">Check Out</button>
            <button onclick="updateInventory(${item.id}, 'In Stock')">Check In</button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    })
    .catch(err => alert('Failed to load inventory: ' + err.message));
}

document.getElementById('inventory-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const btn = document.getElementById('submit-inventory-btn');
  btn.disabled = true;
  btn.textContent = 'Adding...';
  const item_type = document.getElementById('item-type').value;
  const item_id = document.getElementById('item-id').value;
  const status = document.getElementById('item-status').value;
  const location = document.getElementById('item-location').value;
  fetch('/inventory', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
    body: JSON.stringify({ item_type, item_id, status, location })
  })
    .then(res => res.json())
    .then(() => {
      btn.disabled = false;
      btn.textContent = 'Add Item';
      loadInventory();
    })
    .catch(err => {
      btn.disabled = false;
      btn.textContent = 'Add Item';
      alert('Failed to add inventory: ' + err.message);
    });
});

function updateInventory(id, status) {
  fetch('/users')
    .then(res => res.json())
    .then(users => {
      let technicianId = null;
      if (status === 'Checked Out') {
        const select = document.createElement('select');
        users.forEach(user => select.innerHTML += `<option value="${user.id}">${user.name}</option>`);
        technicianId = prompt('Select technician ID:', select.value);
      }
      fetch(`/inventory/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
        body: JSON.stringify({ status, checked_out_to: technicianId })
      })
        .then(() => loadInventory())
        .catch(err => alert('Failed to update inventory: ' + err.message));
    })
    .catch(err => alert('Failed to fetch users: ' + err.message));
}

function loadClients() {
  fetch('/clients')
    .then(res => res.json())
    .then(data => {
      const tbody = document.getElementById('clients-table').querySelector('tbody');
      tbody.innerHTML = '';
      data.forEach(client => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${escapeHtml(client.name)}</td>
          <td>${escapeHtml(client.address)}</td>
          <td>${escapeHtml(client.contact)}</td>
          <td>${escapeHtml(client.notes || '')}</td>
          <td><button onclick="deleteClient(${client.id})">Delete</button></td>
        `;
        tbody.appendChild(tr);
      });
    })
    .catch(err => alert('Failed to load clients: ' + err.message));
}

document.getElementById('client-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const btn = document.getElementById('submit-client-btn');
  btn.disabled = true;
  btn.textContent = 'Adding...';
  const name = document.getElementById('client-name').value;
  const address = document.getElementById('client-address').value;
  const contact = document.getElementById('client-contact').value;
  const notes = document.getElementById('client-notes').value;
  fetch('/clients', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
    body: JSON.stringify({ name, address, contact, notes })
  })
    .then(res => res.json())
    .then(() => {
      btn.disabled = false;
      btn.textContent = 'Add Client';
      loadClients();
    })
    .catch(err => {
      btn.disabled = false;
      btn.textContent = 'Add Client';
      alert('Failed to add client: ' + err.message);
    });
});

function deleteClient(id) {
  if (!confirm('Are you sure you want to delete this client?')) return;
  fetch(`/clients/${id}`, {
    method: 'DELETE',
    headers: { 'CSRF-Token': csrfToken }
  })
    .then(res => {
      if (res.status === 400) return res.json().then(data => { throw new Error(data.error); });
      return res.json();
    })
    .then(() => loadClients())
    .catch(err => alert('Failed to delete client: ' + err.message));
}

function loadIssues() {
  fetch('/issues')
    .then(res => res.json())
    .then(data => {
      const tbody = document.getElementById('issues-table').querySelector('tbody');
      tbody.innerHTML = '';
      data.forEach(issue => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${escapeHtml(issue.clientName)}</td>
          <td>${escapeHtml(issue.title)}</td>
          <td>${escapeHtml(issue.description)}</td>
          <td>${escapeHtml(issue.status)}</td>
          <td>${escapeHtml(issue.assignedTo || '')}</td>
          <td><button onclick="updateIssueStatus(${issue.id}, 'Resolved')">Resolve</button></td>
        `;
        tbody.appendChild(tr);
      });
    })
    .catch(err => alert('Failed to load issues: ' + err.message));
  loadClientsForIssue();
  loadStaffForIssue();
}

function loadClientsForIssue() {
  fetch('/clients')
    .then(res => res.json())
    .then(data => {
      const select = document.getElementById('issue-client-id');
      select.innerHTML = '<option value="">Select Client</option>';
      data.forEach(client => {
        select.innerHTML += `<option value="${client.id}">${escapeHtml(client.name)}</option>`;
      });
    });
}

function loadStaffForIssue() {
  fetch('/users')
    .then(res => res.json())
    .then(data => {
      const select = document.getElementById('issue-assigned-to');
      select.innerHTML = '<option value="">Select Staff</option>';
      data.forEach(user => {
        select.innerHTML += `<option value="${user.id}">${escapeHtml(user.name)}</option>`;
      });
    });
}

document.getElementById('issue-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const btn = document.getElementById('submit-issue-btn');
  btn.disabled = true;
  btn.textContent = 'Logging...';
  const client_id = document.getElementById('issue-client-id').value;
  const title = document.getElementById('issue-title').value;
  const description = document.getElementById('issue-description').value;
  const assigned_to = document.getElementById('issue-assigned-to').value || null;
  fetch('/issues', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
    body: JSON.stringify({ client_id, title, description, assigned_to })
  })
    .then(res => res.json())
    .then(() => {
      btn.disabled = false;
      btn.textContent = 'Log Issue';
      loadIssues();
    })
    .catch(err => {
      btn.disabled = false;
      btn.textContent = 'Log Issue';
      alert('Failed to log issue: ' + err.message);
    });
});

function updateIssueStatus(id, status) {
  fetch(`/issues/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'CSRF-Token': csrfToken },
    body: JSON.stringify({ status })
  })
    .then(() => loadIssues())
    .catch(err => alert('Failed to update issue status: ' + err.message));
}

showLogin();