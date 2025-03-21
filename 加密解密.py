from cryptography.fernet import Fernet
from hashlib import sha256
import base64


# 将提供的密码转换为符合要求的fernet 32字节密钥
def generate_fernet_key(password):
    # 将密钥编码为字节
    password_bytes = password.encode('utf-8')

    # 使用SHA-256哈希函数生成32字节的摘要
    hash_bytes = sha256(password_bytes).digest()

    # 将哈希值转换为Base64编码的32字节密钥
    fernet_key = base64.urlsafe_b64encode(hash_bytes)
    return fernet_key


# 加密函数
def encrypt(text, key):
    cipher = Fernet(key)
    encrypted = cipher.encrypt(text.encode('utf-8'))
    return encrypted


# 解密函数
def decrypted(encrypted, key):
    cipher = Fernet(key)
    decrypted = cipher.decrypt(encrypted).decode('utf-8')
    return decrypted


# 设置密码
password = "qwertyuiop123456"
# 十六位密码（也可以设置更长或稍短，越长越安全）

text = "nothing is impossible"

# 生成fernet密钥
key = generate_fernet_key(password)

# 加密
encrypted = encrypt(text,key)
print("Encrypted:", encrypted)

# 解密
decrypted = decrypted(encrypted, key)
print("Decrypted:", decrypted)


# 对比前后原始文本和解密后的

if text == decrypted:
    print("密码正确，通过")
else:
    print("密码错误，请再次输入")