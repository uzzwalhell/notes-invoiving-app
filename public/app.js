function requireLogin() {
  const token = localStorage.getItem("token");
  if (!token) {
    window.location.href = "/index.html";
  }
}

function logout() {
  localStorage.removeItem("token");
  localStorage.removeItem("username");
  window.location.href = "/index.html";
}

async function apiGet(url) {
  const token = localStorage.getItem("token");
  const response = await fetch(url, {
    headers: { "Authorization": `Bearer ${token}` }
  });
  if (response.status === 401) {
    logout();
    return;
  }
  return response.json();
}

async function apiPost(url, body) {
  const token = localStorage.getItem("token");
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
    body: JSON.stringify(body)
  });
  if (response.status === 401) {
    logout();
    return;
  }
  return response.json();
}

async function apiPut(url, body) {
  const token = localStorage.getItem("token");
  const response = await fetch(url, {
    method: "PUT",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
    body: JSON.stringify(body)
  });
  if (response.status === 401) {
    logout();
    return;
  }
  return response.json();
}

async function apiDelete(url) {
  const token = localStorage.getItem("token");
  const response = await fetch(url, {
    method: "DELETE",
    headers: { "Authorization": `Bearer ${token}` }
  });
  if (response.status === 401) {
    logout();
    return;
  }
  return response.json();
}