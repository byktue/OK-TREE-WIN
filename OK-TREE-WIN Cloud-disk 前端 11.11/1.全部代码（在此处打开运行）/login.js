// login.js - 云盘登录功能实现（修复：跨域兼容+登录逻辑对齐）
document.addEventListener('DOMContentLoaded', function() {
    // 配置常量（与后端接口完全对齐）
    const CONFIG = {
        API_URL: 'http://localhost:3000/api/auth/login', // 后端登录接口地址
        TIMEOUT: 15000,
        TOKEN_KEY: 'cloudDiskToken',
        USER_KEY: 'currentUser'
    };

    // 元素引用
    const loginForm = document.getElementById('loginForm');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const errorMessage = document.getElementById('errorMessage');
    const togglePassword = document.getElementById('togglePassword');
    const successMessage = document.getElementById('successMessage') || errorMessage;

    // 密码显示/隐藏切换
    togglePassword.addEventListener('click', function() {
        togglePasswordVisibility(passwordInput, this);
    });

    function togglePasswordVisibility(input, button) {
        const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
        input.setAttribute('type', type);
        const icon = button.querySelector('i');
        icon.className = type === 'password' ? 'fa fa-eye-slash' : 'fa fa-eye';
    }

    // 表单提交处理
    loginForm.addEventListener('submit', async function(event) {
        event.preventDefault();
        
        hideError();
        if (successMessage !== errorMessage) hideSuccess();
        
        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();
        
        const validation = validateForm(username, password);
        if (!validation.isValid) {
            showError(validation.message);
            return;
        }
        
        setLoadingState(true);
        
        try {
            console.log('发起登录请求：', { username, api: CONFIG.API_URL });
            const { result, response } = await sendLoginRequest({ username, password });
            
            console.log('后端返回结果：', result);
            console.log('响应状态码：', response.status);
            
            const isSuccess = (result.success === true || result.success === 'true') && 
                              (response.status === 200 || response.status === 201);
            
            if (isSuccess) {
                const token = result.data?.token || result.token;
                const user = result.data?.user || result.user;
                
                if (!token || !user) {
                    throw new Error('登录成功，但未获取到认证信息');
                }
                
                localStorage.setItem(CONFIG.TOKEN_KEY, token);
                localStorage.setItem(CONFIG.USER_KEY, JSON.stringify(user));
                
                showSuccess('登录成功！正在跳转...');
                setTimeout(() => {
                    window.location.href = 'file-manager.html';
                }, 1500);
            } else {
                showError(result.message || '登录失败，请检查用户名和密码');
            }
        } catch (error) {
            console.error('登录失败详细错误：', {
                message: error.message,
                name: error.name,
                stack: error.stack
            });
            handleLoginError(error);
        } finally {
            setLoadingState(false);
        }
    });

    // 表单验证
    function validateForm(username, password) {
        if (!username) return { isValid: false, message: '请输入用户名' };
        if (!password) return { isValid: false, message: '请输入密码' };
        return { isValid: true };
    }

    // 发送登录请求（精简跨域头，适配后端）
    async function sendLoginRequest(loginData) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), CONFIG.TIMEOUT);

            const response = await fetch(CONFIG.API_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(loginData),
                signal: controller.signal,
                credentials: 'include'
            });

            clearTimeout(timeoutId);
            console.log('登录响应头：', Object.fromEntries(response.headers));

            let result;
            try {
                result = await response.json();
            } catch (e) {
                const text = await response.text().catch(() => '');
                result = {
                    success: false,
                    message: text || `登录失败（状态码：${response.status}，非JSON响应）`
                };
            }

            if (result.success === undefined) result.success = false;
            if (!result.message) result.message = result.success ? '登录成功' : '登录失败';

            if (!isValidLoginResponse(result)) {
                result = {
                    success: false,
                    message: '服务器返回数据格式错误'
                };
            }

            return { result, response };
            
        } catch (error) {
            if (error.name === 'AbortError') {
                throw new Error('请求超时，请检查网络连接');
            }
            
            if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
                throw new Error('网络连接失败，请检查网络或后端服务是否正常');
            }
            
            throw error;
        }
    }

    // 验证登录响应格式
    function isValidLoginResponse(result) {
        return result && (typeof result.success === 'boolean' || typeof result.success === 'string');
    }

    // 处理登录错误
    function handleLoginError(error) {
        const errorMessageMap = {
            'Failed to fetch': '跨域请求失败，请检查后端CORS配置',
            'NetworkError': '网络异常，请检查网络连接',
            '请求超时': '请求超时，请检查网络稳定性',
            '服务器返回数据格式错误': '服务器响应异常，请联系管理员',
            '401': '认证失败，请重新登录',
            '403': '跨域请求被拒绝（后端CORS未配置）',
            '404': '登录接口不存在，请检查API地址',
            '500': '服务器内部错误，请稍后重试',
            'token/user缺失': '登录成功，但未获取到认证信息'
        };

        let message = error.message;
        if (message.startsWith('{') && message.endsWith('}')) {
            try {
                const errorObj = JSON.parse(message);
                message = errorObj.message || message;
            } catch (e) {}
        }

        message = errorMessageMap[message] || message || '登录失败，请稍后重试';
        
        if (message.includes('跨域') || error.message.includes('CORS') || error.message.includes('Failed to fetch')) {
            message += '（后端需配置：Access-Control-Allow-Origin、Allow-Methods、Allow-Headers）';
        }
        
        showError(message);
    }

    // 显示/隐藏提示与加载状态
    function showError(message) {
        if (!errorMessage) return;
        errorMessage.textContent = message;
        errorMessage.classList.remove('hidden', 'text-green-500');
        errorMessage.classList.add('text-red-500', 'block');
        highlightInvalidFields();
        setTimeout(() => hideError(), 5000);
    }

    function showSuccess(message) {
        if (!successMessage) return;
        successMessage.textContent = message;
        successMessage.classList.remove('hidden', 'text-red-500');
        successMessage.classList.add('text-green-500', 'block');
    }

    function hideError() {
        if (errorMessage) {
            errorMessage.classList.add('hidden');
            errorMessage.classList.remove('text-green-500');
            errorMessage.classList.add('text-red-500');
            clearFieldHighlights();
        }
    }

    function hideSuccess() {
        if (successMessage && successMessage !== errorMessage) {
            successMessage.classList.add('hidden');
            successMessage.classList.remove('text-green-500');
        }
    }

    function highlightInvalidFields() {
        if (!usernameInput.value.trim()) {
            usernameInput.classList.add('border-red-500', 'focus:border-red-500');
            usernameInput.addEventListener('input', function handleInput() {
                usernameInput.classList.remove('border-red-500', 'focus:border-red-500');
                usernameInput.removeEventListener('input', handleInput);
            });
        }
        
        if (!passwordInput.value.trim()) {
            passwordInput.classList.add('border-red-500', 'focus:border-red-500');
            passwordInput.addEventListener('input', function handleInput() {
                passwordInput.classList.remove('border-red-500', 'focus:border-red-500');
                passwordInput.removeEventListener('input', handleInput);
            });
        }
    }

    function clearFieldHighlights() {
        usernameInput.classList.remove('border-red-500', 'focus:border-red-500');
        passwordInput.classList.remove('border-red-500', 'focus:border-red-500');
    }

    function setLoadingState(isLoading) {
        const submitButton = loginForm.querySelector('button[type="submit"]');
        if (!submitButton) return;
        
        const buttonText = submitButton.querySelector('span');
        const buttonIcon = submitButton.querySelector('i');
        
        if (isLoading) {
            submitButton.disabled = true;
            buttonText?.textContent && (buttonText.textContent = '登录中...');
            buttonIcon?.className && (buttonIcon.className = 'fa fa-spinner fa-spin');
            submitButton.classList.add('opacity-70', 'cursor-not-allowed');
        } else {
            submitButton.disabled = false;
            buttonText?.textContent && (buttonText.textContent = '登录');
            buttonIcon?.className && (buttonIcon.className = 'fa fa-arrow-right transform group-hover:translate-x-1 transition-all-300');
            submitButton.classList.remove('opacity-70', 'cursor-not-allowed');
        }
    }

    // 输入框动画与登录状态检查
    function initInputAnimations() {
        const inputs = [usernameInput, passwordInput];
        inputs.forEach(input => {
            input?.addEventListener('focus', function() {
                this.parentElement.classList.add('scale-[1.02]');
            });
            input?.addEventListener('blur', function() {
                this.parentElement.classList.remove('scale-[1.02]');
            });
        });
    }

    function checkLoginStatus() {
        const token = localStorage.getItem(CONFIG.TOKEN_KEY);
        const user = localStorage.getItem(CONFIG.USER_KEY);
        if (token && user) {
            console.log('已登录，直接跳转');
            window.location.href = 'file-manager.html';
        }
    }

    function init() {
        initInputAnimations();
        checkLoginStatus();
        
        if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
            console.log('开发模式：登录功能已适配后端接口');
            console.log('测试账号：admin/admin123（管理员）、test/test123（普通用户）');
            console.log('API地址：', CONFIG.API_URL);
        }
    }

    init();
});