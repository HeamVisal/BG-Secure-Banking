document.addEventListener("DOMContentLoaded", () => {
  // ── Toast notifications ──
  const toastData = document.querySelectorAll(".toast-data");
  toastData.forEach(el => {
    const category = el.dataset.category || "info";
    const message  = el.dataset.message;
    showToast(message, category);
    el.remove();
  });

  function showToast(message, category) {
    const container = document.getElementById("toast-container");
    if (!container) return;
    const toast = document.createElement("div");
    toast.className = `toast ${category}`;
    const icon = category === "success" ? '<i class="fa-solid fa-circle-check"></i>' : category === "error" ? '<i class="fa-solid fa-circle-xmark"></i>' : '<i class="fa-solid fa-triangle-exclamation"></i>';
    toast.innerHTML = `${icon}<span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateX(20px)";
      toast.style.transition = "all .3s ease";
      setTimeout(() => toast.remove(), 300);
    }, 4500);
  }

  // ── Sidebar mobile toggle ──
  const toggle = document.getElementById("sidebar-toggle");
  const sidebar = document.querySelector(".sidebar");
  if (toggle && sidebar) {
    toggle.addEventListener("click", () => {
      sidebar.classList.toggle("open");
      toggle.innerHTML = sidebar.classList.contains("open") ? '<i class="fa-solid fa-xmark"></i>' : '<i class="fa-solid fa-bars"></i>';
    });
    document.addEventListener("click", e => {
      if (!sidebar.contains(e.target) && !toggle.contains(e.target)) {
        sidebar.classList.remove("open");
        toggle.innerHTML = '<i class="fa-solid fa-bars"></i>';
      }
    });
  }

  // ── Active nav link ──
  const links = document.querySelectorAll(".sidebar nav a");
  links.forEach(link => {
    if (link.href === window.location.href) link.classList.add("active");
  });

  // ── Money-form validation ──
  document.querySelectorAll(".money-form").forEach(form => {
    form.addEventListener("submit", e => {
      const amountInput = form.querySelector('input[name="amount"]');
      if (!amountInput) return;
      const amount = Number(amountInput.value);
      if (!amount || amount <= 0) {
        e.preventDefault();
        showToast("Please enter an amount greater than zero.", "error");
        amountInput.focus();
      }
    });
  });

  // ── Risk gauge color ──
  document.querySelectorAll(".risk-gauge").forEach(gauge => {
    const score = parseInt(gauge.dataset.score || "0", 10);
    const color = score >= 70 ? "#f43f5e" : score >= 40 ? "#f59e0b" : "#10b981";
    const pct = score / 100;
    gauge.style.background = `conic-gradient(${color} ${pct}turn, rgba(255,255,255,0.06) 0turn)`;
    gauge.querySelector(".rg-val").style.color = color;
  });
});
