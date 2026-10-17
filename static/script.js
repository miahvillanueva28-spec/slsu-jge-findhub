
document.addEventListener("DOMContentLoaded", function () {
    // Toast notifications
    function showToast(message, type = "success") {
        let container = document.querySelector(".toast-container");

        if (!container) {
            container = document.createElement("div");
            container.className = "toast-container";
            container.setAttribute("aria-live", "polite");
            document.body.appendChild(container);
        }

        const toast = document.createElement("div");
        toast.className = "toast";

        if (type === "error" || type === "warning") {
            toast.classList.add(type);
        }

        // textContent prevents message text from being treated as HTML
        toast.textContent = message;
        container.appendChild(toast);

        window.setTimeout(function () {
            toast.classList.add("removing");
            window.setTimeout(function () {
                toast.remove();
            }, 300);
        }, 3500);
    }

    // Allow templates to display a toast with data attributes
    document.querySelectorAll("[data-toast-message]").forEach(function (el) {
        const message = el.getAttribute("data-toast-message");
        const type = el.getAttribute("data-toast-type") || "success";

        if (message) {
            showToast(message, type);
        }
    });

    // Image preview modal
    let modal = document.querySelector(".image-modal");

    if (!modal) {
        modal = document.createElement("div");
        modal.className = "image-modal";
        modal.setAttribute("role", "dialog");
        modal.setAttribute("aria-modal", "true");
        modal.setAttribute("aria-label", "Image preview");

        const closeButton = document.createElement("button");
        closeButton.className = "image-modal-close";
        closeButton.type = "button";
        closeButton.setAttribute("aria-label", "Close image preview");
        closeButton.textContent = "×";

        const preview = document.createElement("img");
        preview.alt = "Enlarged item photo";

        modal.append(closeButton, preview);
        document.body.appendChild(modal);

        closeButton.addEventListener("click", closeImageModal);
        modal.addEventListener("click", function (event) {
            if (event.target === modal) closeImageModal();
        });
    }

    function closeImageModal() {
        modal.classList.remove("open");
        const preview = modal.querySelector("img");
        if (preview) preview.removeAttribute("src");
    }

    document.querySelectorAll("[data-image-preview], .report-photo").forEach(
        function (img) {
            img.addEventListener("click", function () {
                const source = img.dataset.imagePreview || img.src;
                const preview = modal.querySelector("img");

                if (source && preview) {
                    preview.src = source;
                    modal.classList.add("open");
                }
            });
        }
    );

    document.addEventListener("keydown", function (event) {
        if (event.key === "Escape") closeImageModal();
    });

    // Prevent double submissions and show loading state
    document.querySelectorAll("form[data-loading-form]").forEach(function (form) {
        form.addEventListener("submit", function (event) {
            if (form.dataset.submitting === "true") {
                event.preventDefault();
                return;
            }

            if (!form.checkValidity()) return;

            form.dataset.submitting = "true";

            const button = form.querySelector(
                'button[type="submit"], input[type="submit"]'
            );

            if (button) {
                button.disabled = true;

                if (button.tagName === "BUTTON") {
                    button.dataset.originalText = button.textContent;
                    button.textContent = "Please wait...";
                } else {
                    button.dataset.originalText = button.value;
                    button.value = "Please wait...";
                }
            }
        });
    });

    // Local image preview on report/claim forms
    document.querySelectorAll('input[type="file"][data-image-input]').forEach(
        function (input) {
            input.addEventListener("change", function () {
                const file = input.files && input.files[0];
                const targetSelector = input.dataset.previewTarget;
                const target = targetSelector
                    ? document.querySelector(targetSelector)
                    : null;

                if (!file) {
                    if (target) target.removeAttribute("src");
                    return;
                }

                if (!file.type.startsWith("image/")) {
                    showToast("Pumili ng valid na image file.", "error");
                    input.value = "";
                    if (target) target.removeAttribute("src");
                    return;
                }

                if (file.size > 5 * 1024 * 1024) {
                    showToast("Ang image ay dapat 5 MB o mas mababa.", "error");
                    input.value = "";
                    if (target) target.removeAttribute("src");
                    return;
                }

                if (target) {
                    target.src = URL.createObjectURL(file);
                    target.hidden = false;
                }
            });
        }
    );
});
