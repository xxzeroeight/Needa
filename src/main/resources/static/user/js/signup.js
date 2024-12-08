document.getElementById('signup-form').addEventListener('submit', (e) => {
    e.preventDefault();

    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    if (password !== confirmPassword) {
        alert('비밀번호가 일치하지 않습니다.');
        return ;
    }

    const requestObject = {
        nickname: document.getElementById('nickname').value,
        email: document.getElementById('email').value,
        password: password
    };

    fetch('/api/signup', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestObject)
    })
        .then(response => {
            if (!response.ok) {
                throw new Error('회원가입 중 오류가 발생했습니다.');
            }
        })
        .then(data => {
            window.location.href = '/login';
        })
        .catch(error => {
            console.error(error.message);
        })
})