// register.js - 云盘注册功能实现
document.addEventListener('DOMContentLoaded', function() {
    // 配置常量
    const CONFIG = {
        // 实际的后端API端点 - 根据你的后端配置修改这个URL
        API_URL: 'http://localhost:3000/api/register', // 示例URL   后端API地址
        TIMEOUT: 10000, // 10秒超时
        MAX_RETRIES: 2, // 最大重试次数
        RETRY_DELAY: 1000 // 重试延迟(ms)
    };

    // 元素引用
    const registerForm = document.getElementById('registerForm');
    const togglePassword = document.getElementById('togglePassword');
    const toggleConfirmPassword = document.getElementById('toggleConfirmPassword');
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirmPassword');
    const errorMessage = document.getElementById('errorMessage');
    const successMessage = document.getElementById('successMessage');
    let strengthBar = document.querySelector('.strength-bar');
    let strengthText = document.querySelector('.strength-text');

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

    toggleConfirmPassword.addEventListener('click', function() {
        togglePasswordVisibility(confirmPasswordInput, this);
    });

    function togglePasswordVisibility(input, button) {
        const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
        input.setAttribute('type', type);
        
        const icon = button.querySelector('i');
        icon.className = type === 'password' ? 'fa fa-eye-slash' : 'fa fa-eye';
    }

    // 密码强度检测
    passwordInput.addEventListener('input', function() {
        updatePasswordStrength(this.value);
    });

    function updatePasswordStrength(password) {
        let strength = 0;
        let strengthLevel = '';
        
        // 长度检查
        if (password.length >= 8) strength += 1;
        
        // 包含数字
        if (/\d/.test(password)) strength += 1;
        
        // 包含字母
        if (/[a-zA-Z]/.test(password)) strength += 1;
        
        // 包含特殊字符
        if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) strength += 1;
        
        // 更新强度条和文本
        const strengthPercent = (strength / 4) * 100;
        strengthBar.style.width = strengthPercent + '%';
        
        // 设置颜色和文本
        if (strengthPercent === 0) {
            strengthBar.style.backgroundColor = '#e5e7eb'; // 灰色 - 无密码
            strengthLevel = '';
        } else if (strengthPercent <= 25) {
            strengthBar.style.backgroundColor = '#ef4444'; // 红色
            strengthLevel = '弱';
        } else if (strengthPercent <= 50) {
            strengthBar.style.backgroundColor = '#f59e0b'; // 黄色
            strengthLevel = '中';
        } else if (strengthPercent <= 75) {
            strengthBar.style.backgroundColor = '#3b82f6'; // 蓝色
            strengthLevel = '强';
        } else {
            strengthBar.style.backgroundColor = '#10b981'; // 绿色
            strengthLevel = '非常强';
        }
        
        // 更新强度文本
        strengthText.textContent = strengthLevel;
    }

    // 表单提交处理
    registerForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        // 清除之前的信息
        hideMessages();
        
        // 获取表单数据
        const formData = {
            username: document.getElementById('username').value.trim(),
            password: passwordInput.value,
            confirmPassword: confirmPasswordInput.value
        };
        
        // 前端验证
        const validation = validateForm(formData);
        if (!validation.isValid) {
            showError(validation.message);
            return;
        }
        
        // 显示加载状态
        setLoadingState(true);
        
        try {
            // 调用后端注册接口（带重试机制）
            const result = await registerUserWithRetry(formData);
            
            if (result.success) {
                showSuccess(result.message);
                // 显示系统账号
                displaySystemAccount(result.data.systemId);
                // 保存用户信息到本地存储（可选）
                saveUserInfoToLocalStorage(result.data);
                // 自动跳转到登录页面
                setTimeout(() => {
                    window.location.href = 'login.html';
                }, 2000);
            } else {
                showError(result.message);
            }
        } catch (error) {
            console.error('注册失败:', error);
            handleRegistrationError(error);
        } finally {
            setLoadingState(false);
        }
    });

    // 表单验证
    function validateForm(data) {
        // 用户名验证
        const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
        if (!usernameRegex.test(data.username)) {
            return {
                isValid: false,
                message: '用户名需3-20位，只能包含字母、数字和下划线'
            };
        }
        
        // 密码验证
        const passwordRegex = /^(?=.*[a-zA-Z])(?=.*\d).{6,20}$/;
        if (!passwordRegex.test(data.password)) {
            return {
                isValid: false,
                message: '密码需6-20位，必须包含字母和数字'
            };
        }
        
        // 确认密码验证
        if (data.password !== data.confirmPassword) {
            return {
                isValid: false,
                message: '两次输入的密码不一致'
            };
        }
        
        return { isValid: true };
    }

    // 带重试机制的注册函数
    async function registerUserWithRetry(userData, retries = getConfig().MAX_RETRIES) {
        for (let attempt = 0; attempt <= retries; attempt++) {
            try {
                const result = await registerUser(userData);
                return result;
            } catch (error) {
                console.warn(`注册尝试 ${attempt + 1} 失败:`, error);
                
                if (attempt === retries) {
                    throw error; // 最后一次尝试仍然失败
                }
                
                // 等待一段时间后重试
                await new Promise(resolve => setTimeout(resolve, getConfig().RETRY_DELAY));
            }
        }
    }

    // 调用后端注册API（带超时处理）
    async function registerUser(userData) {
        const config = getConfig();
        
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), config.TIMEOUT);

            const response = await fetch(config.API_URL, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest' // 标识AJAX请求
                },
                body: JSON.stringify({
                    username: userData.username,
                    password: userData.password
                }),
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
            if (!isValidResponse(result)) {
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
                return simulateBackendResponse(userData);
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

    // 验证响应格式
    function isValidResponse(result) {
        return result && typeof result.success === 'boolean';
    }

    // 错误处理
    function handleRegistrationError(error) {
        const errorMessageMap = {
            'Failed to fetch': '网络连接失败，请检查网络设置',
            'NetworkError': '网络错误，请稍后重试',
            '请求超时': '请求超时，请检查网络连接',
            '服务器返回数据格式错误': '服务器响应异常，请稍后重试'
        };

        const message = errorMessageMap[error.message] || 
                       error.message || 
                       '注册失败，请稍后重试';
        
        showError(message);
    }

    // 保存用户信息到本地存储
    function saveUserInfoToLocalStorage(userData) {
        try {
            localStorage.setItem('lastRegisteredUser', JSON.stringify({
                username: userData.username,
                systemId: userData.systemId,
                timestamp: new Date().toISOString()
            }));
        } catch (error) {
            console.warn('无法保存用户信息到本地存储:', error);
        }
    }

    // 模拟后端响应（开发测试用）
    function simulateBackendResponse(userData) {
        // 模拟网络延迟
        return new Promise(resolve => {
            setTimeout(() => {
                // 模拟用户名重复检查
                const existingUsers = ['admin', 'test', 'user123'];
                if (existingUsers.includes(userData.username)) {
                    resolve({
                        success: false,
                        message: '用户名已存在，请选择其他用户名'
                    });
                    return;
                }
                
                // 生成11位系统账号
                const systemId = generateSystemId();
                
                resolve({
                    success: true,
                    message: '注册成功！',
                    data: {
                        systemId: systemId,
                        username: userData.username
                    }
                });
            }, 1000);
        });
    }

    // 生成11位系统账号
    function generateSystemId() {
        const timestamp = Date.now().toString();
        const random = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
        return (timestamp + random).slice(-11);
    }

    // 显示系统账号
    function displaySystemAccount(systemId) {
        const systemAccountInput = document.querySelector('input[value="注册后自动生成11位账号"]');
        systemAccountInput.value = systemId;
        systemAccountInput.classList.remove('text-gray-400', 'bg-gray-50');
        systemAccountInput.classList.add('text-green-600', 'bg-green-50', 'border-green-200');
    }

    // 显示错误信息
    function showError(message) {
        errorMessage.textContent = message;
        errorMessage.classList.remove('hidden');
        successMessage.classList.add('hidden');
        
        // 错误信息自动隐藏
        setTimeout(() => {
            hideMessages();
        }, 5000);
    }

    // 显示成功信息
    function showSuccess(message) {
        successMessage.textContent = message;
        successMessage.classList.remove('hidden');
        errorMessage.classList.add('hidden');
    }

    // 隐藏所有信息
    function hideMessages() {
        errorMessage.classList.add('hidden');
        successMessage.classList.add('hidden');
    }

    // 设置加载状态
    function setLoadingState(isLoading) {
        const submitButton = registerForm.querySelector('button[type="submit"]');
        const buttonText = submitButton.querySelector('span');
        const buttonIcon = submitButton.querySelector('i');
        
        if (isLoading) {
            submitButton.disabled = true;
            buttonText.textContent = '注册中...';
            buttonIcon.className = 'fa fa-spinner fa-spin';
            submitButton.classList.add('opacity-70', 'cursor-not-allowed');
        } else {
            submitButton.disabled = false;
            buttonText.textContent = '注册';
            buttonIcon.className = 'fa fa-user-plus transform group-hover:translate-x-1 transition-all-300';
            submitButton.classList.remove('opacity-70', 'cursor-not-allowed');
        }
    }

    // 初始化密码强度条样式
    function initPasswordStrengthBar() {
        const passwordStrength = document.querySelector('.password-strength');
        // 检查是否已经初始化过
        if (!passwordStrength.querySelector('.strength-text')) {
            passwordStrength.innerHTML = `
                <div class="flex justify-between text-xs mb-1">
                    <span class="text-gray-600">密码强度</span>
                    <span class="strength-text text-gray-600"></span>
                </div>
                <div class="w-full bg-gray-200 rounded-full h-2">
                    <div class="strength-bar h-2 rounded-full transition-all duration-300" style="width: 0%"></div>
                </div>
            `;
        }
        // 重新获取元素引用
        strengthBar = document.querySelector('.strength-bar');
        strengthText = document.querySelector('.strength-text');
    }

    // 初始化
    initPasswordStrengthBar();

    // 开发环境提示
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
        console.log('开发模式: 注册功能已启用模拟数据支持');
    }
});