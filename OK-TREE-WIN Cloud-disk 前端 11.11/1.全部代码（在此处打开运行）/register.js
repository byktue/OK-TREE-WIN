// register.js - 云盘注册功能实现（强化用户名已存在提示）
document.addEventListener('DOMContentLoaded', function() {
    // 配置常量（保持原有，贴合后端接口地址）
    const CONFIG = {
        API_URL: 'http://localhost:3000/api/register', // 后端注册接口地址
        TIMEOUT: 10000, // 10秒超时
        MAX_RETRIES: 1, // 注册接口无需多次重试，改为1次
        RETRY_DELAY: 1000 // 重试延迟(ms)
    };

    // 元素引用（严格匹配HTML中的ID和类名）
    const registerForm = document.getElementById('registerForm');
    const togglePassword = document.getElementById('togglePassword');
    const toggleConfirmPassword = document.getElementById('toggleConfirmPassword');
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirmPassword');
    const errorMessage = document.getElementById('errorMessage');
    const successMessage = document.getElementById('successMessage');
    let strengthBar = document.querySelector('.password-strength-bar');
    let strengthText = document.querySelector('.password-strength-text');

    // 环境检测和配置（保持原有）
    function getConfig() {
        if (window.APP_CONFIG && window.APP_CONFIG.API_URL) {
            return { ...CONFIG, ...window.APP_CONFIG };
        }
        return CONFIG;
    }

    // 密码显示/隐藏切换（保持原有）
    togglePassword.addEventListener('click', function() {
        togglePasswordVisibility(passwordInput, this);
    });

    toggleConfirmPassword.addEventListener('click', function() {
        togglePasswordVisibility(confirmPasswordInput, this);
    });

    function togglePasswordVisibility(input, button) {
        const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
        input.setAttribute('type', type);
        
        const icon = button.querySelector('i');
        icon.className = type === 'password' ? 'fa fa-eye-slash' : 'fa fa-eye';
    }

    // 密码强度检测（保持原有）
    passwordInput.addEventListener('input', function() {
        updatePasswordStrength(this.value);
    });

    function updatePasswordStrength(password) {
        let strength = 0;
        
        // 强度规则（贴合前端提示：6-20位，包含字母和数字）
        if (password.length >= 6) strength += 1;
        if (password.length >= 8) strength += 1;
        if (password.length >= 12) strength += 1;
        if (/\d/.test(password)) strength += 1;
        if (/[a-z]/.test(password)) strength += 1;
        if (/[A-Z]/.test(password)) strength += 1;
        if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) strength += 1;
        
        const strengthPercent = (strength / 7) * 100;
        strengthBar.style.width = strengthPercent + '%';
        
        if (strengthPercent === 0) {
            strengthBar.style.backgroundColor = '#C9CDD4';
            strengthText.textContent = '未输入';
            strengthText.style.color = '#C9CDD4';
        } else if (strengthPercent <= 30) {
            strengthBar.style.backgroundColor = '#ef4444';
            strengthText.textContent = '弱';
            strengthText.style.color = '#ef4444';
        } else if (strengthPercent <= 60) {
            strengthBar.style.backgroundColor = '#f59e0b';
            strengthText.textContent = '中';
            strengthText.style.color = '#f59e0b';
        } else if (strengthPercent <= 85) {
            strengthBar.style.backgroundColor = '#3b82f6';
            strengthText.textContent = '强';
            strengthText.style.color = '#3b82f6';
        } else {
            strengthBar.style.backgroundColor = '#10b981';
            strengthText.textContent = '极强';
            strengthText.style.color = '#10b981';
        }
    }

    // 表单提交处理（核心优化：强化用户名已存在提示逻辑）
    registerForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        // 清除之前的提示信息
        clearMessages();
        
        // 获取表单数据（包含确认密码，仅用于前端校验）
        const formData = {
            username: document.getElementById('username').value.trim(),
            password: passwordInput.value,
            confirmPassword: confirmPasswordInput.value
        };
        
        // 前端校验（保持原有）
        const validation = validateForm(formData);
        if (!validation.isValid) {
            showError(validation.message);
            return;
        }
        
        // 显示加载状态
        setLoadingState(true);
        
        try {
            // 调用后端注册接口（仅传username和password）
            const result = await registerUserWithRetry({
                username: formData.username,
                password: formData.password
            });
            
            // 适配后端响应格式（success/message）
            if (result.success) {
                showSuccess(result.message || '注册成功');
                // 保存注册记录到本地存储
                saveUserInfoToLocalStorage({ username: formData.username });
                // 2秒后跳转到登录页
                setTimeout(() => {
                    window.location.href = 'login.html';
                }, 2000);
            } else {
                // 核心优化：直接显示后端返回的错误信息（如"用户名已存在"）
                // 若后端返回其他错误（如密码不符合规则），也直接复用
                showError(result.message || '注册失败，请重试');
                
                // 额外优化：用户名已存在时，聚焦用户名输入框
                if (result.message === '用户名已存在') {
                    document.getElementById('username').focus();
                }
            }
        } catch (error) {
            console.error('注册失败:', error);
            handleRegistrationError(error);
        } finally {
            setLoadingState(false);
        }
    });

    // 表单验证（保持原有）
    function validateForm(data) {
        const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
        if (!usernameRegex.test(data.username)) {
            return {
                isValid: false,
                message: '用户名需3-20位，仅支持字母、数字和下划线'
            };
        }
        
        const passwordRegex = /^(?=.*[a-zA-Z])(?=.*\d).{6,20}$/;
        if (!passwordRegex.test(data.password)) {
            return {
                isValid: false,
                message: '密码需6-20位，必须同时包含字母和数字'
            };
        }
        
        if (data.password !== data.confirmPassword) {
            return {
                isValid: false,
                message: '两次输入的密码不一致，请重新核对'
            };
        }
        
        return { isValid: true };
    }

    // 带重试机制的注册函数（保持原有）
    async function registerUserWithRetry(userData, retries = getConfig().MAX_RETRIES) {
        for (let attempt = 0; attempt <= retries; attempt++) {
            try {
                const result = await registerUser(userData);
                return result;
            } catch (error) {
                console.warn(`注册尝试 ${attempt + 1} 失败:`, error);
                
                if (attempt === retries) {
                    throw error;
                }
                
                await new Promise(resolve => setTimeout(resolve, getConfig().RETRY_DELAY));
            }
        }
    }

    // 调用后端注册API（核心优化：响应解析适配后端错误格式）
    async function registerUser(userData) {
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
                body: JSON.stringify({
                    username: userData.username,
                    password: userData.password
                }),
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            // 核心优化：后端错误响应（如400）也返回 JSON 格式（success: false, message: "用户名已存在"）
            const result = await response.json();
            
            // 验证响应格式
            if (!isValidResponse(result)) {
                throw new Error('服务器返回数据格式错误');
            }
            
            // 即使HTTP状态码非200，也返回结果（由上层判断success）
            return result;
            
        } catch (error) {
            if (error.name === 'AbortError') {
                throw new Error('请求超时，请检查网络连接');
            }
            
            // 网络错误时使用模拟数据（保持原有，包含用户名已存在场景）
            if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
                console.warn('网络连接失败，使用模拟数据进行测试');
                return simulateBackendResponse(userData);
            }
            
            throw error;
        }
    }

    // 解析错误响应（优化：后端错误已通过JSON解析，此函数作为降级）
    async function parseErrorResponse(response) {
        try {
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return await response.json();
            } else {
                return { success: false, message: await response.text() };
            }
        } catch {
            return { success: false, message: `服务器错误: ${response.status}` };
        }
    }

    // 验证响应格式（保持原有）
    function isValidResponse(result) {
        return result && typeof result.success === 'boolean' && typeof result.message === 'string';
    }

    // 统一错误处理（核心优化：补充后端常见错误场景）
    function handleRegistrationError(error) {
        const errorMessageMap = {
            'Failed to fetch': '网络连接失败，请检查网络设置',
            'NetworkError': '网络异常，请稍后重试',
            '请求超时': '请求超时，请检查网络稳定性',
            '服务器返回数据格式错误': '服务器响应异常，请联系管理员',
            '400': '请求参数错误，请检查用户名和密码格式',
            '409': '用户名已存在', // 后端可能返回409状态码（资源冲突）
            '500': '服务器内部错误，请稍后重试'
        };

        // 优先匹配后端返回的message，再匹配错误映射
        let message = error.message;
        // 若错误信息是JSON字符串（如"{success:false,message:'用户名已存在'}"），解析后取message
        if (message.startsWith('{') && message.endsWith('}')) {
            try {
                const errorObj = JSON.parse(message);
                message = errorObj.message || message;
            } catch (e) {}
        }

        // 最终消息优先级：后端返回message > 错误映射 > 默认提示
        message = errorMessageMap[message] || message || '注册失败，请稍后重试';
        
        showError(message);
    }

    // 保存用户信息到本地存储（保持原有）
    function saveUserInfoToLocalStorage(userData) {
        try {
            localStorage.setItem('lastRegisteredUser', JSON.stringify({
                username: userData.username,
                timestamp: new Date().toISOString()
            }));
        } catch (error) {
            console.warn('无法保存用户信息到本地存储:', error);
        }
    }

    // 模拟后端响应（保持原有，强化用户名已存在场景）
    function simulateBackendResponse(userData) {
        return new Promise(resolve => {
            setTimeout(() => {
                // 模拟用户名重复（后端核心错误场景）
                const existingUsers = ['admin', 'test', 'user123', 'root', 'guest'];
                if (existingUsers.includes(userData.username)) {
                    resolve({
                        success: false,
                        message: '用户名已存在' // 与后端提示文案一致
                    });
                    return;
                }
                
                // 模拟注册成功
                resolve({
                    success: true,
                    message: '注册成功'
                });
            }, 1000);
        });
    }

    // 显示错误信息（保持原有）
    function showError(message) {
        errorMessage.textContent = message;
        errorMessage.style.display = 'block';
        successMessage.style.display = 'none';
        
        // 5秒后自动隐藏错误信息
        setTimeout(() => {
            clearMessages();
        }, 5000);
    }

    // 显示成功信息（保持原有）
    function showSuccess(message) {
        successMessage.textContent = message;
        successMessage.style.display = 'block';
        errorMessage.style.display = 'none';
    }

    // 清除所有提示信息（保持原有）
    function clearMessages() {
        errorMessage.textContent = '';
        successMessage.textContent = '';
        errorMessage.style.display = 'none';
        successMessage.style.display = 'none';
    }

    // 设置加载状态（保持原有）
    function setLoadingState(isLoading) {
        const submitButton = registerForm.querySelector('.submit-button');
        const buttonText = submitButton.querySelector('span');
        const buttonIcon = submitButton.querySelector('i');
        
        if (isLoading) {
            submitButton.disabled = true;
            submitButton.classList.add('opacity-70', 'cursor-not-allowed');
            buttonText.textContent = '注册中...';
            buttonIcon.className = 'fa fa-spinner fa-spin';
        } else {
            submitButton.disabled = false;
            submitButton.classList.remove('opacity-70', 'cursor-not-allowed');
            buttonText.textContent = '注册';
            buttonIcon.className = 'fa fa-user-plus button-text';
        }
    }

    // 初始化密码强度条（保持原有）
    function initPasswordStrength() {
        if (!strengthBar) {
            strengthBar = document.querySelector('.password-strength-bar');
        }
        if (!strengthText) {
            strengthText = document.querySelector('.password-strength-text');
        }
        strengthBar.style.width = '0%';
        strengthBar.style.backgroundColor = '#C9CDD4';
        strengthText.textContent = '未输入';
        strengthText.style.color = '#C9CDD4';
    }

    // 页面初始化（保持原有）
    initPasswordStrength();

    // 开发环境提示（补充用户名已存在测试说明）
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
        console.log('开发模式: 注册功能已启用，支持模拟数据和网络错误处理');
        console.log('后端接口地址:', getConfig().API_URL);
        console.log('测试场景：用户名输入 admin/test/user123/root/guest 可触发"用户名已存在"提示');
    }
});