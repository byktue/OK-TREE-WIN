### （一）注册页

网站注册页面的实现逻辑，包括前端交互验证和后端数据处理的完整流程。

1.  **前端逻辑** - 用户在浏览器中看到和交互的部分。
2.  **后端逻辑** - 服务器端处理核心业务和数据验证的部分。
   
#### 1. 前端实现逻辑

**HTML结构设计：**
- 响应式布局：左侧品牌区域在桌面端显示，移动端隐藏
- 表单区域包含：用户名输入、密码输入、确认密码输入、系统账号展示
- 密码强度可视化展示区域
- 错误/成功消息提示区域

**JavaScript交互功能：**

##### 1.1 实时表单验证
```javascript
// 用户名格式验证：3-20位，字母、数字、下划线
const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;

// 密码格式验证：6-20位，必须包含字母和数字
const passwordRegex = /^(?=.*[a-zA-Z])(?=.*\d).{6,20}$/;

// 确认密码一致性验证
if (data.password !== data.confirmPassword) {
    return { isValid: false, message: '两次输入的密码不一致' };
}
```

##### 1.2 密码强度实时检测
实现四维度密码强度评估：
- **长度检查**：≥8位字符
- **数字包含**：至少一个数字
- **字母包含**：至少一个字母
- **特殊字符**：包含特殊字符加分

强度等级显示：
- 0%：无输入（灰色）
- 1-25%：弱（红色，"弱"）
- 26-50%：中（黄色，"中"）
- 51-75%：强（蓝色，"强"）
- 76-100%：非常强（绿色，"非常强"）

##### 1.3 用户体验优化
- **密码可见性切换**：点击眼睛图标切换密码显示/隐藏
- **加载状态反馈**：注册过程中按钮显示加载动画和禁用状态
- **实时提示信息**：输入时实时显示格式要求和错误信息
- **成功状态展示**：注册成功后系统账号高亮显示

##### 1.4 系统账号生成逻辑
```javascript
function generateSystemId() {
    const timestamp = Date.now().toString(); // 获取时间戳
    const random = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
    return (timestamp + random).slice(-11); // 确保11位长度
}
```

#### 2. 前端与后端交互设计

##### 2.1 前端为后端完成的工作

**数据预处理与验证：**
```javascript
// 1. 输入数据清洗和格式化
const formData = {
    username: document.getElementById('username').value.trim(), // 去除前后空格
    password: passwordInput.value,
    confirmPassword: confirmPasswordInput.value
};

// 2. 前端格式验证（减轻后端压力）
const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
const passwordRegex = /^(?=.*[a-zA-Z])(?=.*\d).{6,20}$/;
```

**请求标准化封装：**
```javascript
// 3. 标准化API请求
const response = await fetch(API_URL, {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json', // 明确指定JSON格式
    },
    body: JSON.stringify({
        username: userData.username,
        password: userData.password  // 原始密码，后端需要加密
    })
});
```

##### 2.2 为后端预留的接口规范

前端代码期望后端接口遵循以下规范：

**核心注册接口：**
```javascript
// 实际的后端API端点 - 根据你的后端配置修改这个URL
const API_URL = 'http://localhost:3000/api/register'; // 示例URL

// 请求规范
POST /api/register
Headers: {
    "Content-Type": "application/json"
}
Body: {
    "username": "string (3-20位字母数字下划线)",
    "password": "string (6-20位，包含字母和数字)"
}

// 成功响应规范（HTTP 200）
{
    "success": true,
    "message": "注册成功描述文本",
    "data": {
        "systemId": "string (11位唯一系统账号)"
    }
}

// 失败响应规范
{
    "success": false,
    "message": "具体错误描述信息"
}
```

**错误状态码映射：**
- `400 Bad Request` - 请求数据格式错误
- `409 Conflict` - 用户名已存在
- `500 Internal Server Error` - 服务器内部错误
- `503 Service Unavailable` - 服务不可用

**数据验证流程**
```
前端提交 → 后端接收 → 格式验证 → 业务验证 → 数据处理 → 返回结果
```

##### 2.3 后端开发人员操作指南

**数据库设计-用户表结构：**
```sql
CREATE TABLE users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    system_account VARCHAR(11) UNIQUE NOT NULL COMMENT '系统账号',
    username VARCHAR(20) UNIQUE NOT NULL COMMENT '用户名',
    password_hash VARCHAR(255) NOT NULL COMMENT '加密密码',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    status TINYINT DEFAULT 1 COMMENT '账户状态: 1-正常, 0-禁用',
    INDEX idx_username (username),
    INDEX idx_system_account (system_account)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户表';
```

#####  2.4数据流架构

```
用户输入 → 前端验证 → API请求 → 后端处理 → 数据库操作
                                      ↓
用户界面 ← 响应处理 ← API响应 ← 结果返回
```
