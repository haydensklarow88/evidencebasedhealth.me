// Navigation toggle (mobile)
function toggleMenu() {
  const navLinks = document.querySelector('.nav-links');
  navLinks.classList.toggle('open');
}

// Close mobile menu on link click
document.querySelectorAll('.nav-links a').forEach(function (link) {
  link.addEventListener('click', function () {
    document.querySelector('.nav-links').classList.remove('open');
  });
});

// Contact form submission handler
function handleSubmit(event) {
  event.preventDefault();
  const status = document.getElementById('form-status');
  status.textContent = 'Thank you! Your message has been received.';
  event.target.reset();
}

// Smooth scroll offset for sticky header
document.querySelectorAll('a[href^="#"]').forEach(function (anchor) {
  anchor.addEventListener('click', function (e) {
    const targetId = this.getAttribute('href');
    if (targetId === '#') return;
    const target = document.querySelector(targetId);
    if (!target) return;
    e.preventDefault();
    const headerHeight = document.querySelector('.site-header').offsetHeight;
    const targetTop = target.getBoundingClientRect().top + window.scrollY - headerHeight - 16;
    window.scrollTo({ top: targetTop, behavior: 'smooth' });
  });
});
