#ifndef TI_AES
#define TI_AES

extern unsigned char AES_default_key[];

// Шифруем пакет (и выравниваем размер к 16 байтам)
uint16_t aes_encrypt_packet(uint8_t *data, uint16_t size);
// Дешифруем пакет (с размером, кратным 16 байт)
uint16_t aes_decrypt_packet(uint8_t *data, uint16_t size);
uint8_t aes_decrypt_boot_packet(uint8_t *data, uint16_t size);

void set_cryptokey(uint8_t *key);

// Подсчет контрольной суммы по iButton
uint8_t CRC8(uint8_t *data, uint16_t len);

#endif


//rep.header[0] = 'P';
//rep.header[1] = personalKeyMode() ? 'F' : '9';
//rep.cell[rep.tcp_size] = CRC8(rep.header, rep.tcp_size + 2);
//full_size = aes_encrypt_packet(rep.cell, rep.tcp_size + 1);
//rep.tcp_size += 5;
//full_size += 4;
//rep.tcp_size = __REV16(rep.tcp_size);
