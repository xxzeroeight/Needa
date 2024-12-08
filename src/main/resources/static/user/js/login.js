function eventListener() {
    document.getElementById('login-form').addEventListener('submit', ev => {
        ev.preventDefault();
        login().then(r => { });
    })
}

/**
 * 로그인 기능
 *
 * @returns {Promise<void>}
 */
async function login() {
    try {
        const email = document.getElementById('email').value.trim();
        const password = document.getElementById('password').value.trim();

        if (!email || !password) {
            alert('내용을 모두 입력해주세요.');
            return ;
        }

        const requestObject = {
            email: email,
            password: password
        };

        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestObject)
        })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${ response.status }`);
                }

                return response.json();
            })
            .then(data => {
                localStorage.setItem('accessToken', data.accessToken);

                window.location.href = '/signup';
            });
    } catch (error) {
        console.error(error.message);
    }
}

document.addEventListener('DOMContentLoaded', eventListener);