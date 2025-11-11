// login.js - 云盘登录功能实现
document.addEventListener('DOMContentLoaded', function() {
    // 配置常量
    const CONFIG = {
        API_URL: 'http://localhost:3000/api/auth/login', // 后端API地址
        TIMEOUT: 10000, // 10秒超时
        MAX_RETRIES: 2, // 最大重试次数
        RETRY_DELAY: 1000, // 重试延迟(ms)
        TOKEN_KEY: 'cloudDiskToken',
        USER_KEY: 'currentUser'
    };

    // 元素引用
    const loginForm = document.getElementById('loginForm');
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    const errorMessage = document.getElementById('errorMessage');
    const togglePassword = document.getElementById('togglePassword');

    // 环境检测和配置
    function getConfig() {
        // 从全局变量或环境获取配置
        if (window.APP_CONFIG && window.APP_CONFIG.API_URL) {
            return { ...CONFIG, ...window.APP_CONFIG };
        }
        return CONFIG;
    }

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
        
        // 清除之前的错误
        hideError();
        
        // 获取输入值
        const username = usernameInput.value.trim();
        const password = passwordInput.value.trim();
        
        // 前端验证
        const validation = validateForm(username, password);
        if (!validation.isValid) {
            showError(validation.message);
            return;
        }
        
        // 显示加载状态
        setLoadingState(true);
        
        try {
            // 调用登录接口（带重试机制）
            const result = await loginWithRetry({ username, password });
            
            if (result.success) {
                handleLoginSuccess(result);
            } else {
                showError(result.message || '登录失败，请检查用户名和密码');
            }
        } catch (error) {
            console.error('登录请求错误:', error);
            handleLoginError(error);
        } finally {
            setLoadingState(false);
        }
    });

    // 表单验证
    function validateForm(username, password) {
        if (!username) {
            return {
                isValid: false,
                message: '请输入用户名'
            };
        }
        
        if (!password) {
            return {
                isValid: false,
                message: '请输入密码'
            };
        }
        
        return { isValid: true };
    }

    // 带重试机制的登录函数
    async function loginWithRetry(loginData, retries = getConfig().MAX_RETRIES) {
        for (let attempt = 0; attempt <= retries; attempt++) {
            try {
                const result = await sendLoginRequest(loginData);
                return result;
            } catch (error) {
                console.warn(`登录尝试 ${attempt + 1} 失败:`, error);
                
                if (attempt === retries) {
                    throw error; // 最后一次尝试仍然失败
                }
                
                // 等待一段时间后重试
                await new Promise(resolve => setTimeout(resolve, getConfig().RETRY_DELAY));
            }
        }
    }

    // 发送登录请求（带超时处理）
    async function sendLoginRequest(loginData) {
        const config = getConfig();
        
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), config.TIMEOUT);

            const response = await fetch(config.API_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify(loginData),
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                // 处理不同的HTTP错误状态
                const errorData = await parseErrorResponse(response);
                throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
            }
            
            const result = await response.json();
            
            // 验证响应格式
            if (!isValidLoginResponse(result)) {
                throw new Error('服务器返回数据格式错误');
            }
            
            return result;
            
        } catch (error) {
            if (error.name === 'AbortError') {
                throw new Error('请求超时，请检查网络连接');
            }
            
            // 如果是网络错误，使用模拟数据
            if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
                console.warn('网络连接失败，使用模拟数据进行测试');
                return simulateLoginResponse(loginData);
            }
            
            throw error;
        }
    }

    // 解析错误响应
    async function parseErrorResponse(response) {
        try {
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return await response.json();
            } else {
                return { message: await response.text() };
            }
        } catch {
            return { message: `服务器错误: ${response.status}` };
        }
    }

    // 验证登录响应格式
    function isValidLoginResponse(result) {
        return result && typeof result.success === 'boolean';
    }

    // 处理登录成功
    function handleLoginSuccess(result) {
        const config = getConfig();
        
        // 存储用户信息和token
        localStorage.setItem(config.TOKEN_KEY, result.token);
        localStorage.setItem(config.USER_KEY, JSON.stringify(result.user));
        
        // 显示成功消息
        showSuccess('登录成功！正在跳转...');
        
        // 跳转到文件管理页
        setTimeout(() => {
            window.location.href = 'file-manager.html';
        }, 1500);
    }

    // 处理登录错误
    function handleLoginError(error) {
        const errorMessageMap = {
            'Failed to fetch': '网络连接失败，请检查网络设置',
            'NetworkError': '网络错误，请稍后重试',
            '请求超时': '请求超时，请检查网络连接',
            '服务器返回数据格式错误': '服务器响应异常，请稍后重试'
        };

        const message = errorMessageMap[error.message] || 
                       error.message || 
                       '登录失败，请稍后重试';
        
        showError(message);
    }

    // 模拟登录响应（开发测试用）
    function simulateLoginResponse(loginData) {
        return new Promise(resolve => {
            setTimeout(() => {
                // 模拟用户验证
                const validUsers = [
                    { username: 'admin', password: 'admin123' },
                    { username: 'test', password: 'test123' },
                    { username: 'user123', password: 'user123' },
                   
                ];

                const user = validUsers.find(u => 
                    u.username === loginData.username && 
                    u.password === loginData.password
                );
                
                if (user) {
                    resolve({
                        success: true,
                        message: '登录成功',
                        token: 'simulated_jwt_token_' + Date.now(),
                        user: {
                           username: user.username
                        }
                    });
                } else {
                    resolve({
                        success: false,
                        message: '用户名或密码错误'
                    });
                }
            }, 1000);
        });
    }

    // 显示错误信息
    function showError(message) {
        errorMessage.textContent = message;
        errorMessage.classList.remove('hidden');
        
        // 输入框高亮效果
        highlightInvalidFields();
        
        // 错误信息自动隐藏
        setTimeout(() => {
            hideError();
        }, 5000);
    }

    // 显示成功信息（临时）
    function showSuccess(message) {
        // 临时使用错误提示区域显示成功信息
        errorMessage.textContent = message;
        errorMessage.classList.remove('hidden');
        errorMessage.classList.remove('text-red-500');
        errorMessage.classList.add('text-green-500');
    }

    // 隐藏错误信息
    function hideError() {
        errorMessage.classList.add('hidden');
        errorMessage.classList.remove('text-green-500');
        errorMessage.classList.add('text-red-500');
        
        // 清除输入框高亮
        clearFieldHighlights();
    }

    // 高亮无效字段
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

    // 清除字段高亮
    function clearFieldHighlights() {
        usernameInput.classList.remove('border-red-500', 'focus:border-red-500');
        passwordInput.classList.remove('border-red-500', 'focus:border-red-500');
    }

    // 设置加载状态
    function setLoadingState(isLoading) {
        const submitButton = loginForm.querySelector('button[type="submit"]');
        const buttonText = submitButton.querySelector('span');
        const buttonIcon = submitButton.querySelector('i');
        
        if (isLoading) {
            submitButton.disabled = true;
            buttonText.textContent = '登录中...';
            buttonIcon.className = 'fa fa-spinner fa-spin';
            submitButton.classList.add('opacity-70', 'cursor-not-allowed');
        } else {
            submitButton.disabled = false;
            buttonText.textContent = '登录';
            buttonIcon.className = 'fa fa-arrow-right transform group-hover:translate-x-1 transition-all-300';
            submitButton.classList.remove('opacity-70', 'cursor-not-allowed');
        }
    }

    // 添加输入框动画效果
    function initInputAnimations() {
        const inputs = [usernameInput, passwordInput];
        inputs.forEach(input => {
            input.addEventListener('focus', function() {
                this.parentElement.classList.add('scale-[1.02]');
            });
            
            input.addEventListener('blur', function() {
                this.parentElement.classList.remove('scale-[1.02]');
            });
        });
    }

    // 检查是否已登录（如果已登录则重定向）
    function checkLoginStatus() {
        const config = getConfig();
        const token = localStorage.getItem(config.TOKEN_KEY);
        const user = localStorage.getItem(config.USER_KEY);
        
        if (token && user) {
            // 可选：验证token是否有效
            // 如果已登录，直接跳转到文件管理页
            // window.location.href = 'file-manager.html';
        }
    }

    // 初始化
    function init() {
        initInputAnimations();
        checkLoginStatus();
        
        // 开发环境提示
        if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
            console.log('开发模式: 登录功能已启用模拟数据支持');
            console.log('测试账号: admin/admin123, test/test123, user123/user123');
        }
    }

    // 启动初始化
    init();
});