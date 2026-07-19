# WPS Office 配置文件哈希校验修补程序

本修补程序用于使 WPS Office 的安装程序和主程序（krt.dll）跳过对配置文件的哈希校验。

## 使用方式

```txt
java -jar wps-hash-patcher.jar <filePath>
```

- `filePath`
    - 目标可执行文件
    - 类型：String

将自定义的配置文件结尾的数字签名部分置为长度为 512 的任意十六进制字符串，数字签名部分要以分号开头且独占最后一行（无换行符）。

## 开源许可

本项目根据 MIT 许可证授权，详见 [LICENSE](LICENSE.md) 文件。
