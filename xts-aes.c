// ABDULLAH KILIÇASLAN 2018280085



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

#define XTS_BLOCK_SIZE 16 // AES blok boyutu (128 bit)

typedef struct {
    unsigned char veri[XTS_BLOCK_SIZE];
    unsigned char iv[XTS_BLOCK_SIZE];
} xts_blok;

// XTS-AES şifreleme fonksiyonu
void xts_aes_encrypt_blocks(xts_blok *bloklar, int blok_sayisi, AES_KEY *anahtari1, AES_KEY *anahtari2) {
    unsigned char tweak[XTS_BLOCK_SIZE];
    unsigned char tmp[XTS_BLOCK_SIZE];
    int i, j;

    for (i = 0; i < blok_sayisi; i++) {
        // Tweak hesapla
        memset(tweak, 0, XTS_BLOCK_SIZE);
        ((unsigned long long*)tweak)[0] = i;
        AES_encrypt(tweak, tweak, anahtari2);

        // Veri bloğunu tweak ile XOR'la
        for (j = 0; j < XTS_BLOCK_SIZE; j++) {
            tmp[j] = bloklar[i].veri[j] ^ tweak[j];
        }

        // Şifrele
        AES_encrypt(tmp, bloklar[i].veri, anahtari1);

        // Tekrar tweak ile XOR'la
        for (j = 0; j < XTS_BLOCK_SIZE; j++) {
            bloklar[i].veri[j] ^= tweak[j];
        }
    }
}

// XTS-AES şifre çözme fonksiyonu
void xts_aes_decrypt_blocks(xts_blok *bloklar, int blok_sayisi, AES_KEY *anahtari1, AES_KEY *anahtari2) {
    unsigned char tweak[XTS_BLOCK_SIZE];
    unsigned char tmp[XTS_BLOCK_SIZE];
    int i, j;

    for (i = 0; i < blok_sayisi; i++) {
        // Tweak hesapla
        memset(tweak, 0, XTS_BLOCK_SIZE);
        ((unsigned long long*)tweak)[0] = i;
        AES_encrypt(tweak, tweak, anahtari2);

        // Veri bloğunu tweak ile XOR'la
        for (j = 0; j < XTS_BLOCK_SIZE; j++) {
            tmp[j] = bloklar[i].veri[j] ^ tweak[j];
        }

        // Şifre çöz
        AES_decrypt(tmp, bloklar[i].veri, anahtari1);

        // Tekrar tweak ile XOR'la
        for (j = 0; j < XTS_BLOCK_SIZE; j++) {
            bloklar[i].veri[j] ^= tweak[j];
        }
    }
}

// XTS-AES şifreleme fonksiyonu (dinamik bellek kullanımı)
void xts_aes_encrypt(unsigned char *veri, int veri_boyutu, unsigned char *anahtar1, unsigned char *anahtar2) {
    // AES şifreleme için anahtarlar
    AES_KEY anahtari1, anahtari2;

    // Anahtarları ayarla
    AES_set_encrypt_key(anahtar1, 128, &anahtari1);
    AES_set_encrypt_key(anahtar2, 128, &anahtari2);

    // Veri bloklarını şifrele
    int blok_sayisi = veri_boyutu / XTS_BLOCK_SIZE;
    if (veri_boyutu % XTS_BLOCK_SIZE != 0) {
        blok_sayisi++;
    }

    xts_blok *bloklar = malloc(blok_sayisi * sizeof(xts_blok));
    if (bloklar == NULL) {
        printf("Bellek yetersiz\n");
        return;
    }

    for (int i = 0; i < blok_sayisi; i++) {
        memcpy(bloklar[i].veri, veri + i * XTS_BLOCK_SIZE, XTS_BLOCK_SIZE);
        memset(bloklar[i].iv, 0, XTS_BLOCK_SIZE);
    }

    xts_aes_encrypt_blocks(bloklar, blok_sayisi, &anahtari1, &anahtari2);

    // Şifrelenmiş veriyi geri kopyala
    for (int i = 0; i < blok_sayisi; i++) {
        memcpy(veri + i * XTS_BLOCK_SIZE, bloklar[i].veri, XTS_BLOCK_SIZE);
    }

    free(bloklar);
}

// XTS-AES şifre çözme fonksiyonu (hata işleme)
void xts_aes_decrypt(unsigned char *veri, int veri_boyutu, unsigned char *anahtar1, unsigned char *anahtar2) {
    // AES şifreleme için anahtarlar
    AES_KEY anahtari1, anahtari2;

    // Anahtarları ayarla
    AES_set_decrypt_key(anahtar1, 128, &anahtari1);
    AES_set_decrypt_key(anahtar2, 128, &anahtari2);

    // Veri bloklarını kontrol et
    int blok_sayisi = veri_boyutu / XTS_BLOCK_SIZE;
    if (veri_boyutu % XTS_BLOCK_SIZE != 0) {
        printf("Geçersiz veri boyutu\n");
        return;
    }

    xts_blok *bloklar = malloc(blok_sayisi * sizeof(xts_blok));
    if (bloklar == NULL) {
        printf("Bellek yetersiz\n");
        return;
    }

    for (int i = 0; i < blok_sayisi; i++) {
        memcpy(bloklar[i].veri, veri + i * XTS_BLOCK_SIZE, XTS_BLOCK_SIZE);
        memset(bloklar[i].iv, 0, XTS_BLOCK_SIZE);
    }

    xts_aes_decrypt_blocks(bloklar, blok_sayisi, &anahtari1, &anahtari2);

    // Çözülmüş veriyi geri kopyala
    for (int i = 0; i < blok_sayisi; i++) {
        memcpy(veri + i * XTS_BLOCK_SIZE, bloklar[i].veri, XTS_BLOCK_SIZE);
    }

    free(bloklar);
}

int main() {
    // Örnek kullanım
    unsigned char veri[] = "Bu bir deneme verisidir.";
    int veri_boyutu = strlen((char *)veri) + 1;
    unsigned char anahtar1[16] = "anahtar_1_128bit";
    unsigned char anahtar2[16] = "anahtar_2_128bit";

    printf("Orijinal Veri: %s\n", veri);

    xts_aes_encrypt(veri, veri_boyutu, anahtar1, anahtar2);
    printf("Şifrelenmiş Veri: %s\n", veri);

    xts_aes_decrypt(veri, veri_boyutu, anahtar1, anahtar2);
    printf("Çözülmüş Veri: %s\n", veri);

    return 0;
}
