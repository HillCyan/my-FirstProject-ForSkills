module.exports = {
  hello_print: async function (args, context) {
    const name = args.username || "访客";
    return `你好，${name}！欢迎使用自定义a-demo技能`;
  }
};