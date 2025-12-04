# Persona WASM Crypto Module

WebAssembly加密模块，为Persona浏览器扩展提供安全的客户端加密功能。

## 🎯 功能特性

### 密码哈希
- ✅ **Argon2** - 内存困难型密码哈希算法
- ✅ 密码验证
- ✅ 安全的盐值生成

### 密钥派生
- ✅ **PBKDF2-SHA256** - 基于密码的密钥派生
- ✅ 可配置迭代次数
- ✅ 支持任意长度密钥生成

### 对称加密
- ✅ **AES-256-GCM** - 认证加密
- ✅ 自动nonce生成
- ✅ 防止篡改

### 哈希函数
- ✅ **SHA-256** - 安全哈希
- ✅ Hex输出格式

### 工具函数
- ✅ Base64 编码/解码
- ✅ Hex 编码/解码
- ✅ 安全随机数生成
- ✅ 常量时间字符串比较(防时序攻击)

## 📦 构建

### 安装wasm-pack

```bash
cargo install wasm-pack
```

### 构建WASM模块

```bash
# 进入WASM项目目录
cd browser/wasm-crypto

# 构建用于浏览器的WASM
wasm-pack build --target web --out-dir ../chromium-extension/wasm

# 或构建用于Node.js的WASM
wasm-pack build --target nodejs --out-dir pkg
```

### 构建选项

- `--target web` - 用于浏览器(推荐)
- `--target bundler` - 用于webpack等打包工具
- `--target nodejs` - 用于Node.js环境
- `--release` - 生产构建(默认)
- `--dev` - 开发构建(更快但更大)

## 🚀 使用方法

### 在浏览器中使用

```javascript
import init, {
    hash_password,
    verify_password,
    encrypt_aes256gcm,
    decrypt_aes256gcm,
    derive_key_pbkdf2,
    sha256,
    random_bytes_base64
} from './wasm/persona_wasm_crypto.js';

// 初始化WASM模块
await init();

// 密码哈希
const result = hash_password("my_password");
console.log("Hash:", result.hash());

// 验证密码
const isValid = verify_password("my_password", result.hash());
console.log("Valid:", isValid); // true

// 密钥派生
const key = derive_key_pbkdf2("password", "salt", 100000, 32);
console.log("Key:", key.to_base64());

// 加密数据
const encrypted = encrypt_aes256gcm("Secret message", key.to_base64());
console.log("Ciphertext:", encrypted.ciphertext_base64());
console.log("Nonce:", encrypted.nonce_base64());

// 解密数据
const decrypted = decrypt_aes256gcm(
    encrypted.ciphertext_base64(),
    encrypted.nonce_base64(),
    key.to_base64()
);
console.log("Decrypted:", decrypted);

// SHA-256哈希
const hash = sha256("hello world");
console.log("SHA256:", hash);

// 生成随机密钥
const randomKey = random_bytes_base64(32);
console.log("Random Key:", randomKey);
```

### 在Chrome扩展中使用

```javascript
// background.ts 或 content.ts
import init, * as crypto from './wasm/persona_wasm_crypto.js';

// 在service worker启动时初始化
chrome.runtime.onStartup.addListener(async () => {
    await init();
    console.log("WASM Crypto initialized");
});

// 使用加密功能
async function encryptCredential(username, password, masterKey) {
    await init(); // 确保已初始化

    const data = JSON.stringify({ username, password });
    const encrypted = crypto.encrypt_aes256gcm(data, masterKey);

    return {
        ciphertext: encrypted.ciphertext_base64(),
        nonce: encrypted.nonce_base64()
    };
}
```

## 🔒 安全特性

1. **内存安全** - Rust保证无缓冲区溢出
2. **防时序攻击** - 常量时间比较
3. **安全随机数** - 使用浏览器的`crypto.getRandomValues()`
4. **现代加密算法** - Argon2、AES-GCM、PBKDF2
5. **认证加密** - AES-GCM防止篡改

## 📊 性能

WASM模块经过优化：
- 使用`opt-level = "z"`最小化体积
- 启用LTO(Link Time Optimization)
- 移除调试符号
- 预期体积: ~200-300KB(gzip后~80-100KB)

## 🧪 测试

```bash
# 运行Rust测试
cargo test

# 运行WASM测试(需要浏览器环境)
wasm-pack test --chrome
wasm-pack test --firefox
wasm-pack test --headless --firefox
```

## 📚 API文档

生成文档：

```bash
cargo doc --open
```

## 🔧 故障排除

### WASM初始化失败

确保在使用任何加密函数前调用`await init()`。

### 模块加载错误

检查Content-Security-Policy是否允许WASM:
```
script-src 'self' 'wasm-unsafe-eval';
```

### 体积过大

启用gzip压缩，或考虑仅包含需要的功能。

## 📝 许可证

MIT License
