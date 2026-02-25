namespace Lib;

public static class CSourceStrings
{
    public const string Encoding =
        @"void to_hex(const uint8_t* b, size_t n, char* out) {
  static const char h[]=""0123456789abcdef"";
  for (size_t i=0;i<n;i++) { out[i*2]=h[b[i]>>4]; out[i*2+1]=h[b[i]&0xf]; }
  out[n*2]=0;
}
uint8_t hex_char(char c) {
  if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10;
  if(c>='A'&&c<='F')return c-'A'+10; return 0xff;
}
size_t from_hex(const char* h, uint8_t* out) {
  size_t j=0; for(;h[0]&&h[1];h+=2) { uint8_t a=hex_char(h[0]),b=hex_char(h[1]);
  if(a>15||b>15)break; out[j++]=a<<4|b; } return j;
}
uint32_t read_u32be(const uint8_t* p) { return (p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3]; }
void write_u32be(uint32_t v, uint8_t* p) { p[0]=v>>24;p[1]=v>>16;p[2]=v>>8;p[3]=v; }
uint32_t read_u32le(const uint8_t* p) { return p[0]|(p[1]<<8)|(p[2]<<16)|(p[3]<<24); }
void write_u32le(uint32_t v, uint8_t* p) { p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24; }";

    public const string Bitwise =
        @"void xor_inplace(uint8_t* a, const uint8_t* b, size_t n) { for(size_t i=0;i<n;i++) a[i]^=b[i]; }
void xor_buf(const uint8_t* a, const uint8_t* b, uint8_t* out, size_t n) { for(size_t i=0;i<n;i++) out[i]=a[i]^b[i]; }
uint32_t rotl32(uint32_t v, int n) { n&=31; return (v<<n)|(v>>(32-n)); }
uint32_t rotr32(uint32_t v, int n) { n&=31; return (v>>n)|(v<<(32-n)); }
uint32_t swap32(uint32_t v) { return ((v&0xff)<<24)|((v&0xff00)<<8)|((v&0xff0000)>>8)|((v&0xff000000)>>24); }
int get_bit(uint32_t v, int b) { return (v>>b)&1; }
uint32_t set_bit(uint32_t v, int b, int on) { return on? v|(1u<<b) : v&~(1u<<b); }";

    public const string Sbox =
        @"static const uint8_t vm[256]={{VM}};
static const uint8_t vm_inv[256]={{VM_INV}};
void vm_apply(uint8_t* b, size_t n) { for (size_t i = 0; i < n; i++) b[i] = vm[b[i]]; }
void vm_apply_inv(uint8_t* b, size_t n) { for (size_t i = 0; i < n; i++) b[i] = vm_inv[b[i]]; }
const uint8_t* vm_get(void) { return vm; }
const uint8_t* vm_get_inv(void) { return vm_inv; }";

    public const string Checksum =
        @"static uint32_t crc32_table[256]; static int crc_init;
void crc32_init(void) {
  if(crc_init) return; crc_init=1;
  for(uint32_t i=0;i<256;i++) { uint32_t c=i;
  for(int k=0;k<8;k++) c=(c&1)?(c>>1)^0xedb88320:c>>1; crc32_table[i]=c; }
}
uint32_t crc32(const uint8_t* d, size_t n) {
  crc32_init(); uint32_t crc=0xffffffff;
  for(size_t i=0;i<n;i++) crc=(crc>>8)^crc32_table[(crc^d[i])&0xff];
  return crc^0xffffffff;
}
uint32_t adler32(const uint8_t* d, size_t n) {
  uint32_t a=1,b=0,mod=65521;
  for(size_t i=0;i<n;i++) { a=(a+d[i])%mod; b=(b+a)%mod; }
  return (b<<16)|a;
}
uint8_t xor_checksum(const uint8_t* d, size_t n) {
  uint8_t s=0; for(size_t i=0;i<n;i++) s^=d[i]; return s;
}";

    public const string ChaChaPoly =
        @"#define CHACHA_KEY_LEN 32
#define CHACHA_IV_LEN 12
#define CHACHA_TAG_LEN 16
extern int chacha_poly_decrypt(uint8_t* out, size_t* outlen, const uint8_t* ciphertext, size_t ctlen,
  const uint8_t* key, const uint8_t* iv, const uint8_t* tag, const uint8_t* aad, size_t aadlen);
int chacha_decrypt(uint8_t* out, size_t* outlen, const uint8_t* ciphertext, size_t ctlen,
  const uint8_t* key, const uint8_t* iv, const uint8_t* tag, const uint8_t* aad, size_t aadlen) {
  return chacha_poly_decrypt(out, outlen, ciphertext, ctlen, key, iv, tag, aad, aadlen);
}";

    public const string Main = @"static const uint8_t opcode_action[256]={{OPCODE_ACTION}};
int vm_run(uint8_t* buf, size_t buf_len, const uint8_t* actions, size_t actions_len, const uint8_t* key, size_t key_len) {
  if (!buf || !actions) return -1;
  static const char hex_ch[]=""0123456789abcdef"";
  for (size_t i = 0; i < actions_len; i++) {
    uint8_t idx = opcode_action[actions[i]];
    if (idx == 255) continue;
    switch (idx) {
      case 0: vm_apply(buf, buf_len); break;
      case 1: vm_apply_inv(buf, buf_len); break;
      case 2: if (key && key_len) { for (size_t j = 0; j < buf_len; j++) buf[j] ^= key[j % key_len]; } break;
      case 3: if (key && key_len) { for (size_t j = 0; j < buf_len; j++) buf[j] ^= key[j % key_len]; } break;
      case 4: if (buf_len >= 4) { uint32_t c = crc32(buf, buf_len - 4); write_u32be(c, buf + buf_len - 4); } break;
      case 5: if (buf_len >= 4) { uint32_t a = adler32(buf, buf_len - 4); write_u32be(a, buf + buf_len - 4); } break;
      case 6: if (buf_len >= 1) { uint8_t s = xor_checksum(buf, buf_len - 1); buf[buf_len - 1] = s; } break;
      case 7: if (buf_len >= 2 && (buf_len & 1) == 0) { size_t n = buf_len / 2; for (size_t k = n; k > 0;) { k--; uint8_t b = buf[k]; buf[2*k] = (uint8_t)hex_ch[b>>4]; buf[2*k+1] = (uint8_t)hex_ch[b&0xf]; } } break;
      case 8: if (buf_len >= 2 && (buf_len & 1) == 0) { size_t n = buf_len / 2; for (size_t k = 0; k < n; k++) { uint8_t a = hex_char((char)buf[2*k]), b = hex_char((char)buf[2*k+1]); if (a > 15 || b > 15) break; buf[k] = (uint8_t)(a<<4|b); } } break;
      case 9: for (size_t k = 0; k + 4 <= buf_len; k += 4) { uint32_t v = read_u32be(buf + k); write_u32le(v, buf + k); } break;
      case 10: for (size_t k = 0; k + 4 <= buf_len; k += 4) { uint32_t v = read_u32le(buf + k); write_u32be(v, buf + k); } break;
      case 11: for (size_t k = 0; k + 4 <= buf_len; k += 4) { uint32_t v = read_u32le(buf + k); write_u32be(v, buf + k); } break;
      case 12: for (size_t k = 0; k + 4 <= buf_len; k += 4) { uint32_t v = read_u32be(buf + k); write_u32le(v, buf + k); } break;
      case 13: if (key && key_len) { int r = key[0] & 31; for (size_t k = 0; k + 4 <= buf_len; k += 4) { uint32_t v = read_u32le(buf + k); write_u32le(rotl32(v, r), buf + k); } } break;
      case 14: if (key && key_len) { int r = key[0] & 31; for (size_t k = 0; k + 4 <= buf_len; k += 4) { uint32_t v = read_u32le(buf + k); write_u32le(rotr32(v, r), buf + k); } } break;
      case 15: for (size_t k = 0; k + 4 <= buf_len; k += 4) { uint32_t v = read_u32le(buf + k); write_u32le(swap32(v), buf + k); } break;
      case 16: break;
      case 17: if (key && key_len >= 2) { int bi = key[0] & 31, on = key[1] & 1; for (size_t k = 0; k + 4 <= buf_len; k += 4) { uint32_t v = read_u32le(buf + k); write_u32le(set_bit(v, bi, on), buf + k); } } break;
      case 18: if (key && key_len >= 60 && buf_len > 16) { size_t outlen = 0; int rc = chacha_decrypt(buf, &outlen, buf, buf_len, key, key + 32, key + 44, (const uint8_t*)0, 0); if (rc != 0) return rc; } break;
      default: break;
    }
  }
  return 0;
}";

    public static string GetAll() =>
        $"#include <stdint.h>\n#include <stddef.h>\n\n{Encoding}\n\n{Bitwise}\n\n{Sbox}\n\n{Checksum}\n\n{ChaChaPoly}\n\n{Main}";
}
