独立复核说明（UID117）

这是模型单轮结束后对冻结版本的复核，不含追问或产物修补。建议评分 3 分，具体事实见 Feedback.md 与 evidence-map.json。模型原轨测试和下列独立测试分开记录。

在 Windows Python 3.14.3 环境安装项目本身及 pytest、cryptography、bcrypt、PyNaCl（具体版本见 environment-reviewed.json）。从冻结提交创建干净 checkout，在 PowerShell 中将 TEMP/TMP 和所有测试临时目录放到自己的缓存目录。

在仓库根目录执行（$verifyCache 为明确指定的缓存目录）：

```powershell
$env:PYTHONPATH=(Get-Location).Path
python -B -m pytest -q -s -p no:cacheprovider tests/test_hostkeys.py tests/test_client.py --basetemp "$verifyCache/regression" --junitxml "$verifyCache/regression.xml" --disable-warnings
python -B -m pytest -q -s -p no:cacheprovider verification/acceptance-r1/test_acceptance.py --basetemp "$verifyCache/acceptance" --junitxml "$verifyCache/acceptance.xml" --disable-warnings
python -B -m pytest -q -s -p no:cacheprovider verification/malformed-r3/test_acceptance.py --basetemp "$verifyCache/malformed" --junitxml "$verifyCache/malformed.xml" --disable-warnings
```

三组结果分别为 78 passed / 2 skipped、22 passed / 2 failed、0 passed / 3 failed。后两组非零退出是如实保留的产物失败。每组均附用例、完整实际命令、原始日志、JUnit XML 和结果摘要。补充组使用同目录 ssh_fixture_helpers.py，不能遗漏该文件；旧 malformed-r2-run 的 helper 路径错误不属于有效成绩。密钥在运行时临时生成，认证仅在本地 socketpair 中进行，不需要容器或外部 SSH 服务。端口/随机指纹/耗时可能变化。

录屏使用另外编写的连接检查控制台调用同版库；并非模型生成的产品 UI。第四个场景如实显示损坏撤销记录仍通过认证的失败。正式轨迹和 MP4 只放飞书相应附件，不放本验证分支。


冻结产物提交：https://github.com/9873199/paramiko-revoked-host-keys/commit/1fc8a7c4c317b31a8076c591e424f03c2d21129e
这些独立验收文件在模型首轮结束后生成，不是模型原轨中的测试。
