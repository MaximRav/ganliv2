function checkLoginAndRedirect(event) {
    event.preventDefault(); // Prevent the default link behavior

    fetch('/isLoggedIn')
        .then(response => response.json())
        .then(data => {
            const isLoggedIn = data.isLoggedIn;

            if (isLoggedIn) {
                window.location.href = event.target.getAttribute('href');
            } else {
                alert('נדרש להתחבר על מנת לצפות ברשימת הגנים');
            }
        });
}