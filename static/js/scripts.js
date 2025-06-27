// Form Validation
function validateForm(event) {
    let inputs = document.querySelectorAll("input[required]");
    for (let input of inputs) {
        if (input.value.trim() === "") {
            alert("Please fill out all required fields.");
            event.preventDefault();
            return;
        }
    }
}

document.addEventListener("DOMContentLoaded", function() {
    let forms = document.querySelectorAll("form");
    for (let form of forms) {
        form.addEventListener("submit", validateForm);
    }
});

// Dark Mode Toggle
function toggleDarkMode() {
    document.body.classList.toggle("dark-mode");
}

document.addEventListener("DOMContentLoaded", function() {
    let toggleButton = document.createElement("button");
    toggleButton.innerText = "Toggle Dark Mode";
    toggleButton.className = "btn btn-secondary mt-2";
    toggleButton.onclick = toggleDarkMode;
    document.body.prepend(toggleButton);
});

document.addEventListener("DOMContentLoaded", function () {
    fetch("/get_score_distribution")
        .then(response => response.json())
        .then(data => {
            let ctx = document.getElementById("scoreChart").getContext("2d");
            new Chart(ctx, {
                type: "bar",
                data: {
                    labels: data.scores,
                    datasets: [{
                        label: "Number of Quizzes",
                        data: data.counts,
                        backgroundColor: "rgba(54, 162, 235, 0.6)"
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: { beginAtZero: true }
                    }
                }
            });
        });
});
