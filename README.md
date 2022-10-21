# NTRUReEncrypt_Attack
We propose an efficient key recovery attack against NTRUReEncrypt(a PRE scheme), whose parameter sets are related NTRU schemes. For specific scheme on parameter sets ees1087ep1, ees1171ep1, ees1499ep1, where N equals 1087, 1171 and 1499 respectively, our experiments are all completed to recover private keys on PC using SageMath 9.6.

Without loss of generality, assume Bob is the attacker. The source code is divided into three modules：
1. We construct an experimentally used encryption system to collect enough ciphtexts and obtain original keys.
2. We build and solve the system of linear equations on F_2 to obtain re-encryt key rk mod2.
3. We recover private keys on Z_q from rk mod2 to obtain Alice's private key sk_A modq.

See paper on Indocrypt 2022 for more details.
