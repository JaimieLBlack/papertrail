// PaperTrail frontend utilities

document.addEventListener('DOMContentLoaded', () => {
  // Auto-dismiss flash messages after 5s
  document.querySelectorAll('.alert-dismissible').forEach(el => {
    setTimeout(() => {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(el);
      bsAlert.close();
    }, 5000);
  });
});
