import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from context import Context
from utils.markdown import build_guide


class TestGuide(unittest.TestCase):
    def test_build_guide_no_crash(self):
        ctx = Context(plaintext="", key_bytes=b"\x00" * 16)
        guide = build_guide(ctx)
        self.assertIsInstance(guide, str)

    def test_build_guide_has_seven_headings(self):
        ctx = Context(plaintext="Hello", key_bytes=b"\x00" * 16)
        guide = build_guide(ctx)
        expected = [
            "## 0. 本次样本",
            "## 1. 明文分组与 PKCS#7 填充",
            "## 2. 密钥扩展",
            "## 3. 加密过程（第 1 轮详解 + 第 2–10 轮快照）",
            "## 4. 解密过程（逆序详解 + 明文比对）",
            "## 5. 分组模式对比（ECB / CBC / GCM）",
            "## 6. 篡改检测（CBC 静默出错 vs GCM 认证失败）",
            "## 7. 安全说明与结论",
        ]
        for h in expected:
            self.assertIn(h, guide)


if __name__ == "__main__":
    unittest.main()
