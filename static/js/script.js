document.addEventListener("DOMContentLoaded", function () {

    function refreshDashboard() {

        const totalLogins = document.getElementById("totalLogins");

        if (!totalLogins) {
            return;
        }

        fetch("/api/dashboard-stats")
            .then(response => response.json())
            .then(data => {

                document.getElementById("totalLogins").textContent =
                    data.total_logins;

                document.getElementById("failedLogins").textContent =
                    data.failed_logins;

                document.getElementById("lowRisk").textContent =
                    data.low;

                document.getElementById("mediumRisk").textContent =
                    data.medium;

                document.getElementById("highRisk").textContent =
                    data.high;

            })
            .catch(error => {

                console.error(
                    "Dashboard refresh failed:",
                    error
                );

            });

    }

    refreshDashboard();

    setInterval(refreshDashboard, 5000);

});