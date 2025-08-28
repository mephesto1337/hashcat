/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#define DEBUG_MESSAGES 0

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct pbewithsha256and256bitaes_cbc_bc_tmp
{
  u32 iv_bytes[8];
  u32 key_bytes[8];
} pbewithsha256and256bitaes_cbc_bc_tmp_t;

typedef struct pbewithsha256and256bitaes_cbc_bc
{
  u32 cipher[64];
  u32 cipher_len;
} pbewithsha256and256bitaes_cbc_bc_t;

DECLSPEC void AES256_decrypt_cbc (PRIVATE_AS const u32 *ks1, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, PRIVATE_AS u32 *iv, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  AES256_decrypt (ks1, in, out, s_td0, s_td1, s_td2, s_td3, s_td4);

  out[0] ^= iv[0];
  out[1] ^= iv[1];
  out[2] ^= iv[2];
  out[3] ^= iv[3];

  iv[0] = in[0];
  iv[1] = in[1];
  iv[2] = in[2];
  iv[3] = in[3];
}



#if DEBUG_MESSAGES > 0
DECLSPEC void show_buf (PRIVATE_AS u32x *buf, PRIVATE_AS u32x len)
{
  printf(" (%u) = ", len);
  u32 i;
  for (i = 0; i < ((len - 1) >> 2); i++) {
    printf("%08x ", buf[i]);
  }
  switch (len & 3) {
    case 0:
      printf("%08x\n", buf[i]);
      break;
    case 1:
      printf("%02x\n", buf[i] & 0xff);
      break;
    case 2:
      printf("%02x%02x\n", buf[i] & 0xff, (buf[i] >> 8) & 0xff);
      break;
    case 3:
      printf("%02x%02x%02x\n", buf[i] & 0xff, (buf[i] >> 8) & 0xff, (buf[i] >> 16) & 0xff);
      break;
  }
}
#define SHOW_BUF(buf, len) \
  do { \
    if (get_global_id (0) == 0 && get_local_id(0) == 0) { \
      printf("%s", #buf); \
      show_buf(buf, len); \
    } \
  } while (0)
#else
#define SHOW_BUF(buf, len)
#endif

DECLSPEC void memcpy_utf16be (PRIVATE_AS u32x *dst, PRIVATE_AS const u32x *src, PRIVATE_AS u32x len)
{
  u32 i;
  for (i = 0; i < (len - 1) >> 2; i++) {
    dst[2 * i] = ((src[i] & 0xff) << 8) | (((src[i] >> 8) & 0xff) << 24);
    dst[2 * i + 1] = (((src[i] >> 16) & 0xff) << 8) | ((src[i] >> 24) << 24);
  }
  switch (len & 3) {
    case 0:
      dst[2 * i] = ((src[i] & 0xff) << 8) | (((src[i] >> 8) & 0xff) << 24);
      dst[2 * i + 1] = (((src[i] >> 16) & 0xff) << 8) | ((src[i] >> 24) << 24);
      break;
    case 1:
      dst[2 * i] = (src[i] & 0xff) << 8;
      break;
    case 2:
      dst[2 * i] = ((src[i] & 0xff) << 8) | (((src[i] >> 8) & 0xff) << 24);
      break;
    case 3:
      dst[2 * i] = ((src[i] & 0xff) << 8) | (((src[i] >> 8) & 0xff) << 24);
      dst[2 * i + 1] = ((src[i] >> 16) & 0xff) << 8;
      break;
  }
}

KERNEL_FQ KERNEL_FA void m10902_init (KERN_ATTR_TMPS_ESALT (pbewithsha256and256bitaes_cbc_bc_tmp_t, pbewithsha256and256bitaes_cbc_bc_t))
{
  /**
   * base
   * will UTF16-BE encode the password creates `I` and `D` buffers and hash them one time
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha256_ctx_t sha256_ctx;

  u32 p[16] = {0};
  u32 s[16] = {0};

  u32 key_id_bytes[16] = {
    0x01010101, 0x01010101, 0x01010101, 0x01010101, 0x01010101, 0x01010101, 0x01010101, 0x01010101,
    0x01010101, 0x01010101, 0x01010101, 0x01010101, 0x01010101, 0x01010101, 0x01010101, 0x01010101
  };
  u32  iv_id_bytes[16] = {
    0x02020202, 0x02020202, 0x02020202, 0x02020202, 0x02020202, 0x02020202, 0x02020202, 0x02020202,
    0x02020202, 0x02020202, 0x02020202, 0x02020202, 0x02020202, 0x02020202, 0x02020202, 0x02020202
  };

  // Encode password in UTF16-BE and a null byte terminator
  u32 pw_len = pws[gid].pw_len;
  u32 p_offset = 0;
  u8* p_buf = (u8 *)p;

  while (p_offset + pw_len < 64) {
    memcpy_utf16be((u32 *)&p_buf[p_offset], pws[gid].i, pw_len);
    p_offset += (pw_len + 1) << 1;
  }
  if (p_offset < 64) {
    memcpy_utf16be((u32 *)&p_buf[p_offset], pws[gid].i, (64 - p_offset) >> 1);
  }

  // Copy salt already 64 bytes
  for (u32 i = 0; i < 16; i++) {
    s[i] = salt_bufs[SALT_POS_HOST].salt_buf_pc[i];
  }

  sha256_init(&sha256_ctx);
  sha256_update(&sha256_ctx, key_id_bytes, 64);
  sha256_update_swap(&sha256_ctx, s, 64);
  sha256_update_swap(&sha256_ctx, p, 64);
  sha256_final(&sha256_ctx);

  for (u32 i = 0; i < 8; i++) {
    tmps[gid].key_bytes[i] = sha256_ctx.h[i];
  }

  sha256_init(&sha256_ctx);
  sha256_update(&sha256_ctx, iv_id_bytes, 64);
  sha256_update_swap(&sha256_ctx, s, 64);
  sha256_update_swap(&sha256_ctx, p, 64);
  sha256_final(&sha256_ctx);

  for (u32 i = 0; i < 8; i++) {
    tmps[gid].iv_bytes[i] = sha256_ctx.h[i];
  }

#if DEBUG_MESSAGES > 0
  if (gid == 0) {
    SHOW_BUF(pws[gid].i, pw_len);
    SHOW_BUF(p, 64);
    SHOW_BUF(s, 64);
    printf("salt_iter = %u\n", salt_bufs[SALT_POS_HOST].salt_iter);
    SHOW_BUF(tmps[gid].iv_bytes, 32);
    SHOW_BUF(tmps[gid].key_bytes, 32);
  }
#endif
}

KERNEL_FQ KERNEL_FA void m10902_loop (KERN_ATTR_TMPS_ESALT (pbewithsha256and256bitaes_cbc_bc_tmp_t, pbewithsha256and256bitaes_cbc_bc_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  if (LOOP_POS + 1 == salt_bufs[SALT_POS_HOST].salt_iter) return;


  u32x iv[16] = {0};
  u32x key[16] = {0};
  sha256_ctx_t sha256_ctx;

  for (u32 i = 0; i < 8; i++) {
    key[i] = packv (tmps, key_bytes, gid, i);
    iv[i] = packv (tmps, iv_bytes, gid, i);
  }

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, iv, 32);
    sha256_final(&sha256_ctx);
    for (u32 i = 0; i < 8; i++) {
      iv[i] = sha256_ctx.h[i];
    }

    sha256_init(&sha256_ctx);
    sha256_update(&sha256_ctx, key, 32);
    sha256_final(&sha256_ctx);
    for (u32 i = 0; i < 8; i++) {
      key[i] = sha256_ctx.h[i];
    }
    SHOW_BUF(key, 32);
    SHOW_BUF(iv, 16);
  }


  for (u32 i = 0; i < 8; i++) {
    unpackv (tmps, iv_bytes, gid, i, iv[i]);
    unpackv (tmps, key_bytes, gid, i, key[i]);
  }
}

KERNEL_FQ KERNEL_FA void m10902_comp (KERN_ATTR_TMPS_ESALT (pbewithsha256and256bitaes_cbc_bc_tmp_t, pbewithsha256and256bitaes_cbc_bc_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  u32 iv[4];
  u32 key[8];
  u32 cipher_block[64] = {0};
  u32 cipher_len = esalt_bufs[DIGESTS_OFFSET_HOST].cipher_len;
  u32 block_count = cipher_len >> 2;

  for (u32 i = 0; i < 4; i++) {
    iv[i] = packv (tmps, iv_bytes, gid, i);
  }
  for (u32 i = 0; i < 8; i++) {
    key[i] = packv (tmps, key_bytes, gid, i);
  }
  for (u32 i = 0; i < 64; i++) {
    cipher_block[i] = esalt_bufs[DIGESTS_OFFSET_HOST].cipher[i];
  }

  SHOW_BUF(key, 32);
  SHOW_BUF(iv, 16);
  SHOW_BUF(cipher_block, cipher_len);

  u32 ks[60];
  AES256_set_decrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 out[16] = {0};
  sha256_ctx_t sha256_ctx;
  u32 cipher_offset = 0;

  SHOW_BUF(key, 32);
  SHOW_BUF(iv, 16);

  sha256_init(&sha256_ctx);

  u32 offset;
  for (offset = 0; offset + 4 < block_count; offset += 4) {
    AES256_decrypt_cbc(ks, &cipher_block[offset], out, iv, s_td0, s_td1, s_td2, s_td3, s_td4);
    SHOW_BUF(out, 16);
    sha256_update(&sha256_ctx, out, 16);
  }
  // Last block remove padding
  AES256_decrypt_cbc(ks, &cipher_block[offset], out, iv, s_td0, s_td1, s_td2, s_td3, s_td4);

  u32 pad_len = out[3] >> 24;
  u32 outlen = 16;
  if (pad_len < 16) {
    sha256_update(&sha256_ctx, out, 16 - pad_len);
    SHOW_BUF(out, 16 - pad_len);
  }
  sha256_final(&sha256_ctx);
  SHOW_BUF(sha256_ctx.h, 32);

  const u32 r0 = sha256_ctx.h[0];
  const u32 r1 = sha256_ctx.h[1];
  const u32 r2 = sha256_ctx.h[2];
  const u32 r3 = sha256_ctx.h[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
