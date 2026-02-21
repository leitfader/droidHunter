(function () {
  const storageKey = "theme";
  const root = document.documentElement;
  const toggle = document.getElementById("themeToggle");
  const prefersDark =
    window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;

  function normalizeTheme(value) {
    return value === "dark" ? "dark" : "light";
  }

  function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
    if (toggle) {
      toggle.textContent = theme === "dark" ? "Day Mode" : "Night Mode";
      toggle.setAttribute("aria-pressed", theme === "dark" ? "true" : "false");
    }
  }

  let theme = normalizeTheme(localStorage.getItem(storageKey) || (prefersDark ? "dark" : "light"));
  applyTheme(theme);

  if (toggle) {
    toggle.addEventListener("click", () => {
      theme = theme === "dark" ? "light" : "dark";
      localStorage.setItem(storageKey, theme);
      applyTheme(theme);
    });
  }
})();
